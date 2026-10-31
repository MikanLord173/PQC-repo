"""
抗阻斷攻擊實驗 (DDoS / 記憶體耗竭)：「傳統收齊才驗」vs「Early-Drop + 100 槽 LRU + 純記憶體暫存」

比較三種 RSU 重組策略 (後兩者呼叫專案原始程式碼 RSU.main.process_fragment，真實密碼學運算)：
  baseline  傳統收齊才驗：分片依 (msg_id, 來源) 暫存，同序號後到覆蓋先到，不檢查 F1 雜湊承諾、不設會話上限，
            收齊後才做完整雙簽驗證；逾時 (--baseline-timeout，預設 1s) 才釋放。
  ed_v1     Early-Drop + 100 槽 LRU (本次修正前的策略)：滿槽淘汰最早建立的會話、F1 前每序號只留 1 片、
            所有分片計入來源 IP 限流、每收一包就掃描逾時。
  ed_v2     Early-Drop + 100 槽 LRU (修正後)：優先淘汰未認證會話、F1 前每序號留 3 個候選 (保留最先到者)、
            只有 F1 計入來源 IP 限流、逾時掃描最多每 5ms 一次。
三者皆只在記憶體 (RAM) 暫存，不寫磁碟；差別在於暫存是否有上限、偽造分片能否進入暫存。

攻擊情境 (合法車輛 AMB-217 每秒送 1 則 Full 封包，模式 none，通道無掉包，共 --messages 則)：
  flood_big    記憶體耗竭洪水：攻擊者以隨機偽造來源 IP 狂送 1396B 的假 F2 (每片開一個新會話)
  flood_small  會話槽耗竭洪水：同上，但每片只有 8B (同樣頻寬下可開更多會話，用來擠掉合法會話)
  inject       分片注入：攻擊者冒用救護車來源位址，在每個合法後續分片之後補送 k 片同序號的偽造分片
  inject_f1loss 同上，且主 F1 掉包、車輛靠 DUP 尾端備用 F1 (後續分片先於 F1 抵達，需在 F1 前暫存)
  ip_spoof     來源 IP 限流濫用：攻擊者以救護車的 IP 每秒送 R 個垃圾後續分片 (8B)，耗盡該 IP 的限流額度
  ip_spoof_f1  同上，但送的是偽造 F1 (600B，驗簽必失敗)；IP 限流無法分辨真偽，為殘餘風險

時鐘：RSU 讀到的 time.time() 為虛擬時鐘 (依封包抵達時間推進)，逾時與 150ms 時效判斷可重現；
     CPU 耗時另以 perf_counter 量測處理每個封包的實際時間。

輸出 (預設 sim/results/ 底下下一個未使用的編號資料夾)：
  dos_summary.csv        每組 (情境, 攻擊強度, 策略) 的結果
  fig_dos_flood.png/.svg 洪水攻擊：暫存記憶體峰值與合法訊息放行率
  fig_dos_inject.png/.svg 分片注入 / IP 限流濫用：合法訊息放行率與浪費的完整驗證次數
  params.json

用法 (於專案根目錄)：
  python3 -m sim.dos_exp
"""
import argparse, contextlib, csv, json, os, random, struct, sys, time
from collections import OrderedDict
from concurrent.futures import ProcessPoolExecutor

import pki
from sim.trip_sim import VirtualClock, CaptureSock, SIM_EPOCH, _next_run_dir, _git_commit, LINK_OVERHEAD

OBU_ID   = "AMB-217"
OBU_ADDR = ("10.0.0.2", 40000)
RSU_ID   = 1
RATE_BPS = 6e6                         # 802.11p 10 MHz 通道 6 Mbps
VARIANTS = ("baseline", "ed_v1", "ed_v2")
VARIANT_LABEL = {"baseline": "傳統收齊才驗", "ed_v1": "Early-Drop+LRU (修正前)", "ed_v2": "Early-Drop+LRU (修正後)"}

SUMMARY_HEADERS = {
    "scenario": "攻擊情境", "intensity": "攻擊強度", "intensity_unit": "強度單位", "variant": "重組策略",
    "messages": "合法訊息數", "granted": "放行訊息數", "grant_rate_pct": "合法訊息放行率(%)",
    "attack_pkts": "攻擊封包數", "peak_sessions": "暫存會話數峰值", "peak_buffer_kb": "暫存資料量峰值(KB)",
    "full_verifies": "完整雙簽驗證次數", "wasted_verifies": "浪費的完整驗證次數(驗證失敗)",
    "f1_verifies": "F1 ECC 驗證次數", "cpu_ms_total": "RSU 處理總 CPU 時間(ms)",
    "cpu_util_pct": "RSU CPU 使用率(%)", "cpu_us_per_attack_pkt": "每個攻擊封包平均 CPU(µs)",
    "blacklisted": "合法車輛被封鎖(1/0)",
}


def airtime(size):
    """與 sim.trip_sim 相同的 802.11p 空中時間 (取平均退避，不含排隊)。"""
    return 58e-6 + 1.5 * 13e-6 + 40e-6 + 8 * (size + LINK_OVERHEAD) / RATE_BPS


# ─── 傳統收齊才驗 RSU ────────────────────────────────────────────────────────
class BaselineRSU:
    def __init__(self, parse, clock, timeout):
        self.parse, self.clock, self.timeout = parse, clock, timeout
        self.buf = OrderedDict()          # 依建立順序，逾時從頭釋放
        self.bytes = 0
        self.granted = set()
        self.full_verifies = self.wasted = 0

    def prune(self):
        now = self.clock.time()
        while self.buf:
            key, s = next(iter(self.buf.items()))
            if now - s["created"] <= self.timeout:
                break
            self._drop(key)

    def _drop(self, key):
        s = self.buf.pop(key)
        self.bytes -= sum(len(f) for f in s["frags"] if f)

    def process(self, data, addr, sock):
        seq, total, msg_id = struct.unpack('!BBH', data[:4])
        total &= 0x7F
        chunk = data[4:]
        if seq < 1 or total < 1 or seq > total:
            return
        key = (msg_id, addr)
        s = self.buf.get(key)
        if s is None:
            s = self.buf[key] = {"created": self.clock.time(), "frags": [None] * total}
        if seq > len(s["frags"]):
            return
        old = s["frags"][seq - 1]
        self.bytes += len(chunk) - (len(old) if old else 0)
        s["frags"][seq - 1] = chunk                 # 後到覆蓋先到 (無承諾可判斷真偽)
        if all(s["frags"]):
            f1 = s["frags"][0]
            packet = f1[1 + f1[0] * 32:] + b"".join(s["frags"][1:])   # 去掉 F1 開頭的承諾欄位 (傳統設計不使用)
            self._drop(key)
            self.full_verifies += 1
            payload = self.parse.parse_packet(packet, rsu_id=RSU_ID)
            if payload is None:
                self.wasted += 1
                return
            ts = payload["full_timestamp"]
            if self.clock.time() - ts > 0.15 or ts in self.granted:
                return
            self.granted.add(ts)
            sock.sendto(b"granted", addr)

    def stats(self):
        return len(self.buf), self.bytes


# ─── Worker ─────────────────────────────────────────────────────────────────
_W = {}

def _init_worker():
    import RSU.main as rsu
    import RSU.parse as parse
    import RSU.gen_payload as rsu_gen
    import OBU.gen_payload as obu_gen
    from OBU.encode_packet import gen_packet
    from OBU.fragment import make_fragments
    clock = VirtualClock()
    for mod in (rsu, parse, rsu_gen, obu_gen):
        mod.time = clock
    counters = {"f1": 0, "full": 0, "full_fail": 0}
    orig_f1, orig_parse = parse.verify_f1_ecc, parse.parse_packet

    def f1_counted(*a, **k):
        counters["f1"] += 1
        return orig_f1(*a, **k)

    def parse_counted(*a, **k):
        counters["full"] += 1
        r = orig_parse(*a, **k)
        if r is None:
            counters["full_fail"] += 1
        return r

    parse.verify_f1_ecc, parse.parse_packet = f1_counted, parse_counted
    _W.update(rsu=rsu, parse=parse, clock=clock, counters=counters, gen_packet=gen_packet,
              make_fragments=make_fragments, devnull=open(os.devnull, "w"))


def _reset(variant):
    rsu, parse = _W["rsu"], _W["parse"]
    for d in (rsu.reassemble_buffer, rsu.recent_completed, rsu.recent_granted, rsu.id_active_session,
              rsu.id_session_meta, rsu.ip_rate_log, rsu.obu_f1_rate_log, rsu.blacklist):
        d.clear()
    parse.clear_all_caches()
    v2 = variant == "ed_v2"
    rsu.EVICT_UNAUTHENTICATED_FIRST = v2
    rsu.RATE_LIMIT_F1_ONLY = v2
    rsu.PRE_F1_SLOT_CANDIDATES = 3 if v2 else 1
    _W["prune_interval"] = rsu.PRUNE_INTERVAL if v2 else 0.0
    for k in _W["counters"]:
        _W["counters"][k] = 0


def _legit_events(n_msgs, scenario, k_inject, rng):
    """合法車輛 (與攻擊者冒用其位址的注入分片) 的事件：(時間, 封包, 來源, 是否攻擊)。"""
    events, msg_ts = [], []
    for j in range(n_msgs):
        t0 = 0.5 + j * 1.0
        _W["clock"].now = SIM_EPOCH + t0
        with contextlib.redirect_stdout(_W["devnull"]):
            pkt = _W["gen_packet"](OBU_ID, intersection_id=RSU_ID, known_RSU=False)
        frags = _W["make_fragments"](pkt, msg_id=j + 1)
        seq = list(frags)
        if scenario == "inject_f1loss":
            seq = frags[1:] + [frags[0]]               # 主 F1 掉包，尾端備用 F1 最後抵達 (DUP)
        t = t0 + 0.0012                                 # OBU 產生封包耗時
        for f in seq:
            t += airtime(len(f))
            events.append((t, f, OBU_ADDR, False))
            if scenario.startswith("inject") and f[0] >= 2:
                for _ in range(k_inject):             # 偽造同序號分片，緊跟在合法分片之後
                    fake = f[:4] + bytes(rng.getrandbits(8) for _ in range(len(f) - 4))
                    t += airtime(len(fake))
                    events.append((t, fake, OBU_ADDR, True))
        msg_ts.append(t0)
    return events, msg_ts


def _attack_events(scenario, rate, duration, rng):
    if rate <= 0 or scenario not in ("flood_big", "flood_small", "ip_spoof", "ip_spoof_f1"):
        return []
    size = {"flood_big": 1396, "flood_small": 8, "ip_spoof": 8, "ip_spoof_f1": 600}[scenario]
    seq = 1 if scenario == "ip_spoof_f1" else 2
    out, n = [], int(rate * duration)
    for i in range(n):
        t = (i + rng.random()) / rate
        msg_id = rng.randrange(1000, 65536)
        if scenario.startswith("ip_spoof"):
            addr = (OBU_ADDR[0], rng.randrange(1024, 65536))         # 冒用救護車 IP
        else:
            addr = (f"172.{rng.randrange(16, 32)}.{rng.randrange(256)}.{rng.randrange(1, 255)}", rng.randrange(1024, 65536))
        out.append((t, struct.pack('!BBH', seq, 5, msg_id) + b"\xa5" * size, addr, True))
    return out


def _buffer_stats(rsu):
    total = 0
    for s in rsu.reassemble_buffer.values():
        total += sum(len(f) for f in s["fragments"] if f)
        total += sum(len(c) for cands in s.get("pre_f1", {}).values() for c in cands)
        total += sum(len(c) for c in s.get("xor_parity_candidates", []))
    return len(rsu.reassemble_buffer), total


def run_task(task):
    scenario, intensity, variant, args = task
    rng = random.Random(args["seed"])
    rsu, clock, counters = _W["rsu"], _W["clock"], _W["counters"]
    _reset(variant)
    k_inject = intensity if scenario.startswith("inject") else 0
    rate = intensity if not scenario.startswith("inject") else 0
    legit, msg_ts = _legit_events(args["messages"], scenario, k_inject, rng)
    duration = args["messages"] + 1.0
    events = sorted(legit + _attack_events(scenario, rate, duration, rng), key=lambda e: e[0])

    sock = CaptureSock(clock)
    base = BaselineRSU(_W["parse"], clock, args["baseline_timeout"]) if variant == "baseline" else None
    peak_sess = peak_bytes = 0
    cpu = cpu_attack = 0.0
    n_attack = 0
    next_sample = last_prune = -1.0
    with contextlib.redirect_stdout(_W["devnull"]):
        for t, pkt, addr, is_attack in events:
            clock.now = SIM_EPOCH + t
            t0 = time.perf_counter()
            if base is not None:
                base.prune()
                base.process(pkt, addr, sock)
            else:
                if t - last_prune >= _W["prune_interval"]:   # 同 RSU.main.receive_data
                    rsu.prune_expired_sessions()
                    last_prune = t
                rsu.process_fragment(pkt, addr, sock=sock, rsu_id=RSU_ID)
            dt = time.perf_counter() - t0
            cpu += dt
            if is_attack:
                cpu_attack += dt
                n_attack += 1
            if t >= next_sample:                       # 每 5ms 取樣暫存量
                sess, nbytes = base.stats() if base is not None else _buffer_stats(rsu)
                peak_sess, peak_bytes = max(peak_sess, sess), max(peak_bytes, nbytes)
                next_sample = t + 0.005

    if base is not None:
        n_granted = len(base.granted)
        full, wasted = base.full_verifies, base.wasted
    else:
        n_granted = 0
        for _, d in sock.sent:
            st = json.loads(d)["status"][0]["sigStatus"][0]["status"]
            n_granted += st == 4
        full, wasted = counters["full"], counters["full_fail"]
    unit = "forged/frag" if scenario.startswith("inject") else "pkt/s"
    return {
        "scenario": scenario, "intensity": intensity, "intensity_unit": unit, "variant": variant,
        "messages": args["messages"], "granted": n_granted,
        "grant_rate_pct": round(100 * n_granted / args["messages"], 1),
        "attack_pkts": n_attack, "peak_sessions": peak_sess, "peak_buffer_kb": round(peak_bytes / 1024, 1),
        "full_verifies": full, "wasted_verifies": wasted, "f1_verifies": counters["f1"],
        "cpu_ms_total": round(cpu * 1000, 2), "cpu_util_pct": round(100 * cpu / duration, 2),
        "cpu_us_per_attack_pkt": round(1e6 * cpu_attack / n_attack, 2) if n_attack else "",
        "blacklisted": int(OBU_ID in rsu.blacklist),
    }


# ─── 圖表 ──────────────────────────────────────────────────────────────────
VARIANT_COLOR = {"baseline": "#898781", "ed_v1": "#eb6834", "ed_v2": "#2a78d6"}
VARIANT_STYLE = {"baseline": dict(linewidth=4.5, linestyle="solid", zorder=2),       # 粗灰線墊底，重疊時仍看得到
                 "ed_v1": dict(linewidth=2, linestyle=(0, (4, 2)), zorder=3),
                 "ed_v2": dict(linewidth=2, linestyle="solid", zorder=4)}


def _plot(rows, out):
    from sim.poster_exp import _setup_matplotlib, INK
    plt = _setup_matplotlib()

    def series(scenario, metric):
        d = {}
        for r in rows:
            if r["scenario"] == scenario:
                d.setdefault(r["variant"], []).append((r["intensity"], r[metric]))
        return {v: sorted(p) for v, p in d.items()}

    # 圖 1：洪水攻擊
    fig, axes = plt.subplots(1, 3, figsize=(12, 3.9))
    panels = [("flood_big", "peak_buffer_kb", "1396B 假分片洪水：暫存資料量峰值 (KB)", True),
              ("flood_big", "grant_rate_pct", "1396B 假分片洪水：合法訊息放行率 (%)", False),
              ("flood_small", "grant_rate_pct", "8B 假分片洪水：合法訊息放行率 (%)", False)]
    for ax, (sc, metric, title, logy) in zip(axes, panels):
        for v, pts in series(sc, metric).items():
            xs = [max(x, 1) for x, _ in pts]
            ys = [max(y, 0.1) if logy else y for _, y in pts]
            ax.plot(xs, ys, marker="o", color=VARIANT_COLOR[v], markersize=5, label=VARIANT_LABEL[v], **VARIANT_STYLE[v])
        ax.set_xscale("log")
        if logy:
            ax.set_yscale("log")
        else:
            ax.set_ylim(-3, 103)
        ax.axvline(512, color="#c3c2b7", linestyle=(0, (3, 3)), linewidth=1)
        ax.set_title(title, loc="left", fontsize=11, color=INK)
        ax.set_xlabel("攻擊封包速率 (pkt/s，對數；0 畫在 1)\n灰色虛線 ≈ 6Mbps 通道 1400B 封包滿載")
    axes[0].legend(loc="upper left", fontsize=9)
    fig.tight_layout()
    for ext in ("png", "svg"):
        fig.savefig(os.path.join(out, f"fig_dos_flood.{ext}"), dpi=300)
    plt.close(fig)

    # 圖 2：分片注入 / IP 限流濫用 (群組長條)
    groups = [("inject", 1, "注入\nk=1"), ("inject", 3, "注入\nk=3"),
              ("inject_f1loss", 1, "F1 遺失\n+注入 k=1"), ("inject_f1loss", 3, "F1 遺失\n+注入 k=3"),
              ("ip_spoof", 100, "冒用 IP\n垃圾分片\n100/s"), ("ip_spoof", 200, "冒用 IP\n垃圾分片\n200/s"),
              ("ip_spoof_f1", 100, "冒用 IP\n假 F1\n100/s"), ("ip_spoof_f1", 200, "冒用 IP\n假 F1\n200/s")]
    idx = {(r["scenario"], r["intensity"], r["variant"]): r for r in rows}
    groups = [g for g in groups if all((g[0], g[1], v) in idx for v in VARIANTS)]
    fig, axes = plt.subplots(2, 1, figsize=(11, 7.2))
    w = 0.26
    for ax, metric, title in ((axes[0], "grant_rate_pct", "合法訊息放行率 (%)"),
                              (axes[1], "wasted_verifies", "浪費的完整雙簽驗證次數")):
        for i, v in enumerate(VARIANTS):
            xs = [g + (i - 1) * w for g in range(len(groups))]
            ys = [idx[(sc, k, v)][metric] for sc, k, _ in groups]
            ax.bar(xs, ys, width=w, color=VARIANT_COLOR[v], label=VARIANT_LABEL[v], zorder=3)
            for x, y in zip(xs, ys):
                ax.text(x, y, f"{y:g}", ha="center", va="bottom", fontsize=7.5, color=INK)
        ax.set_xticks(range(len(groups)), [g[2] for g in groups], fontsize=9)
        ax.set_title(title, loc="left", fontsize=11, color=INK)
        ax.grid(axis="x", visible=False)
    axes[0].set_ylim(0, 112)
    axes[1].set_ylim(0, max(r["wasted_verifies"] for r in rows) * 1.2 + 1)
    axes[0].legend(loc="lower right", fontsize=9, ncol=3, bbox_to_anchor=(1, 1.06), frameon=False)
    fig.tight_layout()
    for ext in ("png", "svg"):
        fig.savefig(os.path.join(out, f"fig_dos_inject.{ext}"), dpi=300)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser(description="抗阻斷攻擊 (DDoS / 記憶體耗竭) 實驗")
    ap.add_argument("--messages", type=int, default=20, help="合法訊息數 (每秒 1 則，預設 20)")
    ap.add_argument("--flood-rates", default="0,100,500,2000,10000,20000", help="洪水攻擊速率 pkt/s")
    ap.add_argument("--inject-k", default="1,3", help="每個合法分片後補送的偽造分片數")
    ap.add_argument("--spoof-rates", default="100,200", help="冒用救護車 IP 的垃圾封包速率 pkt/s")
    ap.add_argument("--baseline-timeout", type=float, default=1.0, help="傳統策略的重組逾時秒數 (預設 1)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--out", default=None)
    ap.add_argument("--replot", default=None, help="只依既有結果資料夾的 dos_summary.csv 重畫圖表")
    args = ap.parse_args()
    if args.replot:
        with open(os.path.join(args.replot, "dos_summary.csv"), newline="", encoding="utf-8-sig") as f:
            back = {v: k for k, v in SUMMARY_HEADERS.items()}
            rows = [{back[k]: (float(v) if k != "攻擊情境" and k != "強度單位" and k != "重組策略" and v != "" else v)
                     for k, v in r.items()} for r in csv.DictReader(f)]
        for r in rows:
            r["intensity"] = int(r["intensity"])
        _plot(rows, args.replot)
        return
    out = args.out or _next_run_dir()
    os.makedirs(out, exist_ok=True)

    cfg = {"messages": args.messages, "seed": args.seed, "baseline_timeout": args.baseline_timeout}
    tasks = []
    for sc in ("flood_big", "flood_small"):
        tasks += [(sc, int(r), v, cfg) for r in args.flood_rates.split(",") for v in VARIANTS]
    for sc in ("inject", "inject_f1loss"):
        tasks += [(sc, int(k), v, cfg) for k in args.inject_k.split(",") for v in VARIANTS]
    for sc in ("ip_spoof", "ip_spoof_f1"):
        tasks += [(sc, int(r), v, cfg) for r in args.spoof_rates.split(",") for v in VARIANTS]

    t0 = time.perf_counter()
    print(f"共 {len(tasks)} 組 …", file=sys.stderr)
    with ProcessPoolExecutor(max_workers=args.jobs, initializer=_init_worker) as ex:
        rows = list(ex.map(run_task, tasks))
    elapsed = time.perf_counter() - t0

    with open(os.path.join(out, "dos_summary.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(SUMMARY_HEADERS.values())
        for r in rows:
            w.writerow(r[k] for k in SUMMARY_HEADERS)
    _plot(rows, out)

    import RSU.main as rsu
    params = {
        "command": " ".join(["python3 -m sim.dos_exp", *sys.argv[1:]]),
        "git_commit": _git_commit(), "run_at": time.strftime("%Y-%m-%d %H:%M:%S"), "elapsed_s": round(elapsed, 1),
        **cfg, "flood_rates": args.flood_rates, "inject_k": args.inject_k, "spoof_rates": args.spoof_rates,
        "variants": VARIANT_LABEL, "pqc_alg": pki.pqc_alg(),
        "rsu_constants": {"MAX_SESSIONS": rsu.MAX_SESSIONS, "PRUNING_TIMEOUT_s": rsu.PRUNING_TIMEOUT,
                          "IP_MAX_PACKETS_per_s": rsu.IP_MAX_PACKETS, "IP_MAX_TRACKED": rsu.IP_MAX_TRACKED},
        "channel": {"rate_mbps": RATE_BPS / 1e6, "max_1400B_frames_per_s": round(1 / airtime(1400)),
                    "max_12B_frames_per_s": round(1 / airtime(12)), "loss": "none"},
        "notes": ["攻擊封包速率超過單一 6 Mbps 通道上限的點代表多台攻擊裝置或多通道同時攻擊",
                  "ed_v1 以旗標模擬修正前策略 (淘汰最早會話、F1 前每序號 1 片、所有分片計入 IP 限流、每包掃描逾時)"],
    }
    with open(os.path.join(out, "params.json"), "w", encoding="utf-8") as f:
        json.dump(params, f, ensure_ascii=False, indent=2)
    print(f"完成 ({elapsed:.1f}s)，輸出至 {out}/", file=sys.stderr)


if __name__ == "__main__":
    main()
