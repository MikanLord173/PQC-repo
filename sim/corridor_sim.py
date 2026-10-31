"""
多路口連續綠燈廊道 (Green Wave) 與快取機制效率模擬 (Monte Carlo)

情境：救護車依序通過 N 個路口 (預設 4 個，RSU 1 → 2 → 3 → 4，拓樸同 RSU.main.DOWNSTREAM_TOPOLOGY)，
起點距第 1 個路口 --first-distance 公尺，路口間距 --spacing 公尺，固定車速。
每個路口沿用 sim.trip_sim 的發送迴圈：週期性送 SRM 直到該路口放行或車輛抵達該路口。
「綠波達成」= 全部 N 個路口都在車輛抵達前放行。

比較策略：
  independent   各路口獨立驗證：不做有線骨幹預熱，每個路口都是第一次見到此車
                → 車輛送 Full 封包 (公鑰 + CA 後量子憑證)，RSU 冷快取需重構 ECQV 公鑰。
  prewarm_old   先傳給後面的 RSU (修正前 TTL)：上游路口放行後經有線骨幹把 (Q_U, PK_PQC) 推給下游，
                SSM 告知車輛哪些路口已預熱 → 車輛在下游改送 Short。快取 TTL = 300m / 車速 + 30s (與實際間距無關)，
                OBU 白名單固定 60 秒。
  prewarm       同上，TTL 依實際路口間距估算 (間距 / 車速 × 2 + 30s)，並在 SSM 夾帶 TTL 讓 OBU 同步。

快取效率：
  F1 ECQV 快取命中率 = F1 驗證中免重構 Q_U 的比例；PQC 公鑰快取命中 = Short 封包驗證成功 (未回 status=6)。
  Short 失效回退 = 車輛送 Short 但 RSU 快取已過期 / 未預熱，被回 status=6 要求補 Full。

時鐘、通道、運算耗時同 sim.trip_sim (虛擬時鐘 + 802.11p 通道模型 + 固定運算耗時常數)。
--dwell：車輛通過第 1 個路口後在路段中停等 (例如塞車) 的秒數，停等期間不送訊息，用來測試快取 TTL。

輸出 (預設 sim/results/ 底下下一個未使用的編號資料夾)：
  corridor_summary.csv           每組 (環境, 間距, 停等, 策略) 的整趟彙總
  corridor_by_intersection.csv   每個路口的指標
  corridor_trials.csv            每趟次原始紀錄
  fig_corridor.png/.svg          圖 1：各路口觸發時間 / 傳輸量 / RSU 運算 (中掉包環境)
  fig_corridor_cache.png/.svg    圖 2：快取命中率與 Short 失效回退 vs 路口間距 / 停等時間
  params.json

用法 (於專案根目錄)：
  python3 -m sim.corridor_sim
"""
import argparse, contextlib, csv, io, json, math, os, random, sys
import time as _real_time
from concurrent.futures import ProcessPoolExecutor

import pki
import sim.trip_sim as ts
from sim.trip_sim import Channel, CaptureSock, SIM_EPOCH, OBU_ID, OBU_ADDR, _pct, _mean

STRATEGIES = ("independent", "prewarm_old", "prewarm")
STRATEGY_LABEL = {"independent": "各路口獨立驗證", "prewarm_old": "骨幹預熱 (修正前 TTL)",
                  "prewarm": "骨幹預熱 (修正後 TTL)"}
OBU_LEGACY_TTL = 60.0

SUMMARY_HEADERS = {
    "env": "掉包環境", "spacing_m": "路口間距(m)", "dwell_s": "路段停等(s)", "strategy": "策略",
    "trials": "趟次數", "n_intersections": "路口數",
    "wave_rate_pct": "綠波達成率_全部路口放行(%)", "green_rate_pct": "路口放行率_平均(%)",
    "ttg_mean_s": "每路口觸發耗時_平均(s)", "ttg_p95_s": "每路口觸發耗時_P95(s)",
    "first_try_pct": "每路口一次成功率(%)", "attempts_mean": "每路口嘗試次數_平均",
    "bytes_up_trip": "每趟上行傳輸量_平均(B)", "rsu_compute_ms_trip": "每趟 RSU 運算耗時_平均(ms)",
    "f1_cache_hit_pct": "F1 ECQV 快取命中率(%)", "short_msg_pct": "Short 封包占比(%)",
    "short_fallbacks_trip": "每趟 Short 失效回退次數_平均", "ecqv_per_trip": "每趟 ECQV 重構次數_平均",
}
BY_INT_HEADERS = {
    "env": "掉包環境", "spacing_m": "路口間距(m)", "dwell_s": "路段停等(s)", "strategy": "策略",
    "intersection": "路口", "green_rate_pct": "放行率(%)", "ttg_mean_s": "觸發耗時_平均(s)",
    "ttg_p95_s": "觸發耗時_P95(s)", "first_try_pct": "一次成功率(%)", "bytes_up_mean": "上行傳輸量_平均(B)",
    "rsu_compute_ms_mean": "RSU 運算耗時_平均(ms)", "f1_cache_hit_pct": "F1 ECQV 快取命中率(%)",
    "short_first_pct": "首則即為 Short(%)", "short_fallbacks_mean": "Short 失效回退次數_平均",
}
TRIAL_HEADERS = {
    "env": "掉包環境", "spacing_m": "路口間距(m)", "dwell_s": "路段停等(s)", "strategy": "策略", "trial": "趟次",
    "intersection": "路口", "success": "放行(1/0)", "time_to_green_s": "觸發耗時(s)", "attempts": "嘗試次數",
    "bytes_up": "上行傳輸量(B)", "rsu_compute_ms": "RSU 運算耗時(ms)", "f1_verifies": "F1 驗證次數",
    "ecqv": "ECQV 重構次數", "short_msgs": "Short 封包數", "short_fallbacks": "Short 失效回退次數",
    "first_short": "首則即為 Short(1/0)",
}


# ─── Worker ─────────────────────────────────────────────────────────────────
_C = {}

def _init(costs_ms):
    ts._init_worker(costs_ms)
    parse = ts._W["parse"]
    counters = {"f1": 0, "ecqv": 0, "parse": 0}
    f1, ecqv, full = parse.verify_f1_ecc, parse.reconstruct_obu_pubkey, parse.parse_packet

    def f1_c(*a, **k):
        counters["f1"] += 1
        return f1(*a, **k)

    def ecqv_c(*a, **k):
        counters["ecqv"] += 1
        return ecqv(*a, **k)

    def full_c(*a, **k):
        counters["parse"] += 1
        return full(*a, **k)

    parse.verify_f1_ecc, parse.reconstruct_obu_pubkey, parse.parse_packet = f1_c, ecqv_c, full_c
    _C["counters"] = counters


def _configure(strategy, spacing):
    rsu = ts._W["rsu"]
    if strategy == "independent":
        rsu.DOWNSTREAM_TOPOLOGY = {i: {"default": []} for i in range(1, 5)}
    else:
        rsu.DOWNSTREAM_TOPOLOGY = {1: {"default": [2, 3]}, 2: {"default": [3]}, 3: {"default": [4]}, 4: {"default": []}}
    rsu.PREWARM_LEGACY_TTL = strategy == "prewarm_old"
    rsu.DOWNSTREAM_DISTANCE_M = {(1, 2): spacing, (1, 3): 2 * spacing, (2, 3): spacing, (3, 4): spacing}


def _run_trip(args, strategy, ch, n_int, spacing, dwell):
    rsu, clock, costs = ts._W["rsu"], ts._W["clock"], ts._W["costs"]
    cnt = _C["counters"]
    ts._reset_rsu()
    ch.reset()
    known = {}                         # OBU 白名單：{路口: 到期時間 (趟次內相對秒)}
    t, msg_id, rows = 0.0, 0, []
    t_enter = 0.0
    for i in range(1, n_int + 1):
        seg = args.first_distance if i == 1 else spacing
        if i > 1:
            t_enter += dwell           # 通過上一個路口後在路段中停等 (不送訊息)
        t = max(t, t_enter)
        t_arr = t_enter + seg / args.speed_mps
        dist = lambda tt: math.hypot(max(seg - args.speed_mps * max(tt - t_enter, 0.0), 0.0), args.rsu_offset)
        rec = {"attempts": 0, "bytes_up": 0, "green_t": None, "short_msgs": 0, "fallbacks": 0, "first_short": None}
        c0 = dict(cnt)
        while t < t_arr:
            msg_id = (msg_id + 1) % 65536
            rec["attempts"] += 1
            is_known = known.get(i, -1.0) > t
            rec["short_msgs"] += is_known
            if rec["first_short"] is None:
                rec["first_short"] = int(is_known)
            clock.now = SIM_EPOCH + t
            packet = ts._W["gen_packet"](OBU_ID, intersection_id=i, known_RSU=is_known)
            frags = ts._build_fragments(packet, msg_id, args.mode)
            t_tx, arrivals = t + costs["obu_gen"], []
            for f in frags:
                t_end, ok, t_rx = ch.transmit(len(f), t_tx, dist(t_tx))
                rec["bytes_up"] += len(f)
                if ok:
                    arrivals.append((t_rx, f))
                t_tx = t_end
            t_send_end = t_tx
            busy, nack_t = 0.0, None
            sock = CaptureSock(clock)
            for t_rx, f in arrivals:
                clock.now = SIM_EPOCH + max(t_rx, busy)
                rsu.prune_expired_sessions()
                rsu.process_fragment(f, OBU_ADDR, sock=sock, rsu_id=i)
                busy = clock.now - SIM_EPOCH
                for t_ssm, data in sock.sent:
                    ssm = json.loads(data)
                    st = ssm["status"][0]["sigStatus"][0]["status"]
                    t_rel = t_ssm - SIM_EPOCH
                    # 下行 SSM 經同一通道；送達才會更新 OBU 白名單
                    _, ok, t_dl = ch.transmit(len(data), t_rel, dist(t_rel))
                    if st == 4 and rec["green_t"] is None:
                        rec["green_t"] = t_rel
                        if ok:
                            known[i] = t_dl + OBU_LEGACY_TTL
                            ttls = ssm.get("prewarm_ttl_s") if strategy == "prewarm" else None
                            pre = ssm.get("prewarmed_rsus", [])
                            for r, ttl in zip(pre, ttls or [OBU_LEGACY_TTL] * len(pre)):
                                known[r] = t_dl + float(ttl)
                    elif st in (5, 6) and ok and nack_t is None:
                        nack_t = t_dl
                sock.sent.clear()
                if rec["green_t"] is not None:
                    break
            if rec["green_t"] is not None:
                break
            if nack_t is not None:
                rec["fallbacks"] += is_known
                known.pop(i, None)
            wait_end = t_send_end + args.ack_timeout
            if nack_t is not None and nack_t < wait_end:
                wait_end = nack_t
            t = wait_end + args.interval
        d = {k: cnt[k] - c0[k] for k in cnt}
        success = rec["green_t"] is not None and rec["green_t"] <= t_arr
        compute = (d["f1"] * costs["f1_verify"] + d["ecqv"] * costs["ecqv"] + d["parse"] * costs["full_verify"]) * 1000
        rows.append({"intersection": i, "success": int(success),
                     "time_to_green_s": round(rec["green_t"] - t_enter, 6) if success else "",
                     "attempts": rec["attempts"], "bytes_up": rec["bytes_up"], "rsu_compute_ms": round(compute, 4),
                     "f1_verifies": d["f1"], "ecqv": d["ecqv"], "short_msgs": rec["short_msgs"],
                     "short_fallbacks": rec["fallbacks"], "first_short": rec["first_short"] or 0})
        # 車輛抵達並通過路口 i (無論是否放行)，前往下一個路口
        t_enter = t_arr
    return rows


def run_config(task):
    args, env, spacing, dwell, strategy = task
    random.seed(args.seed)
    ch = Channel(env, "iid", args, random.Random(args.seed))
    _configure(strategy, spacing)
    rows = []
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        for trial in range(1, args.trials + 1):
            for r in _run_trip(args, strategy, ch, args.intersections, spacing, dwell):
                rows.append({"env": env, "spacing_m": spacing, "dwell_s": dwell, "strategy": strategy,
                             "trial": trial, **r})
            buf.seek(0); buf.truncate()
    return rows


# ─── 彙總 ──────────────────────────────────────────────────────────────────
def _ratio(a, b):
    return round(100 * a / b, 2) if b else ""


def summarize(rows, n_int):
    groups, by_int = {}, {}
    for r in rows:
        key = (r["env"], r["spacing_m"], r["dwell_s"], r["strategy"])
        groups.setdefault(key, []).append(r)
        by_int.setdefault(key + (r["intersection"],), []).append(r)
    summary = []
    for key, rs in groups.items():
        trips = {}
        for r in rs:
            trips.setdefault(r["trial"], []).append(r)
        ok = [r for r in rs if r["success"]]
        ttg = [r["time_to_green_s"] for r in ok]
        f1 = sum(r["f1_verifies"] for r in rs)
        n_trips = len(trips)
        summary.append({
            "env": key[0], "spacing_m": key[1], "dwell_s": key[2], "strategy": key[3],
            "trials": n_trips, "n_intersections": n_int,
            "wave_rate_pct": _ratio(sum(all(x["success"] for x in tr) for tr in trips.values()), n_trips),
            "green_rate_pct": _ratio(len(ok), len(rs)),
            "ttg_mean_s": _mean(ttg), "ttg_p95_s": _pct(ttg, 95),
            "first_try_pct": _ratio(sum(r["success"] and r["attempts"] == 1 for r in rs), len(rs)),
            "attempts_mean": _mean([r["attempts"] for r in ok]),
            "bytes_up_trip": round(sum(r["bytes_up"] for r in rs) / n_trips, 1),
            "rsu_compute_ms_trip": round(sum(r["rsu_compute_ms"] for r in rs) / n_trips, 3),
            "f1_cache_hit_pct": _ratio(f1 - sum(r["ecqv"] for r in rs), f1),
            "short_msg_pct": _ratio(sum(r["short_msgs"] for r in rs), sum(r["attempts"] for r in rs)),
            "short_fallbacks_trip": round(sum(r["short_fallbacks"] for r in rs) / n_trips, 4),
            "ecqv_per_trip": round(sum(r["ecqv"] for r in rs) / n_trips, 3),
        })
    per_int = []
    for key, rs in by_int.items():
        ok = [r for r in rs if r["success"]]
        ttg = [r["time_to_green_s"] for r in ok]
        f1 = sum(r["f1_verifies"] for r in rs)
        per_int.append({
            "env": key[0], "spacing_m": key[1], "dwell_s": key[2], "strategy": key[3], "intersection": key[4],
            "green_rate_pct": _ratio(len(ok), len(rs)), "ttg_mean_s": _mean(ttg), "ttg_p95_s": _pct(ttg, 95),
            "first_try_pct": _ratio(sum(r["success"] and r["attempts"] == 1 for r in rs), len(rs)),
            "bytes_up_mean": round(sum(r["bytes_up"] for r in rs) / len(rs), 1),
            "rsu_compute_ms_mean": round(sum(r["rsu_compute_ms"] for r in rs) / len(rs), 4),
            "f1_cache_hit_pct": _ratio(f1 - sum(r["ecqv"] for r in rs), f1),
            "short_first_pct": _ratio(sum(r["first_short"] for r in rs), len(rs)),
            "short_fallbacks_mean": round(sum(r["short_fallbacks"] for r in rs) / len(rs), 4),
        })
    return summary, per_int


def _write(path, rows, headers):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(headers.values())
        for r in rows:
            w.writerow(r[k] for k in headers)


# ─── 圖表 ──────────────────────────────────────────────────────────────────
STRAT_COLOR = {"independent": "#898781", "prewarm_old": "#eb6834", "prewarm": "#2a78d6"}


def _plot(summary, per_int, out, base_spacing, env="mid"):
    from sim.poster_exp import _setup_matplotlib, INK
    plt = _setup_matplotlib()

    pick = {(r["strategy"], r["intersection"]): r for r in per_int
            if r["env"] == env and r["spacing_m"] == base_spacing and r["dwell_s"] == 0}
    n_int = max(i for _, i in pick)
    fig, axes = plt.subplots(1, 3, figsize=(12, 3.9))
    panels = [("ttg_mean_s", "各路口平均觸發時間 (s)"), ("bytes_up_mean", "各路口上行傳輸量 (KB)"),
              ("rsu_compute_ms_mean", "各路口 RSU 運算耗時 (ms)")]
    w = 0.27
    for ax, (metric, title) in zip(axes, panels):
        for k, s in enumerate(STRATEGIES):
            xs = [i + (k - 1) * w for i in range(1, n_int + 1)]
            ys = [float(pick[(s, i)][metric] or 0) / (1000 if metric == "bytes_up_mean" else 1)
                  for i in range(1, n_int + 1)]
            ax.bar(xs, ys, width=w, color=STRAT_COLOR[s], label=STRATEGY_LABEL[s], zorder=3)
        ax.set_xticks(range(1, n_int + 1), [f"路口 {i}" for i in range(1, n_int + 1)])
        ax.set_title(title, loc="left", fontsize=11, color=INK)
        ax.grid(axis="x", visible=False)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper right", ncol=3, fontsize=9, frameon=False, bbox_to_anchor=(0.995, 0.995))
    fig.suptitle(f"綠波廊道：{n_int} 個路口、間距 {base_spacing:.0f}m、中掉包環境", x=0.01, ha="left", fontsize=13, color=INK)
    fig.tight_layout(rect=(0, 0, 1, 0.93))
    for ext in ("png", "svg"):
        fig.savefig(os.path.join(out, f"fig_corridor.{ext}"), dpi=300)
    plt.close(fig)

    fig, axes = plt.subplots(1, 2, figsize=(11, 3.9))
    for ax, field, label in ((axes[0], "spacing_m", "路口間距 (m)"), (axes[1], "dwell_s", "路段停等時間 (s)")):
        for s in STRATEGIES:
            if field == "spacing_m":
                pts = sorted((r["spacing_m"], r["short_fallbacks_trip"]) for r in summary
                             if r["strategy"] == s and r["env"] == env and r["dwell_s"] == 0)
            else:
                pts = sorted((r["dwell_s"], r["short_fallbacks_trip"]) for r in summary
                             if r["strategy"] == s and r["env"] == env and r["spacing_m"] == base_spacing)
            if pts:
                ax.plot(*zip(*pts), marker="o", color=STRAT_COLOR[s], linewidth=2, label=STRATEGY_LABEL[s])
        ax.set_xlabel(label)
        ax.set_title("每趟 Short 失效回退次數 (快取過期 → status=6 補 Full)", loc="left", fontsize=11, color=INK)
    axes[0].legend(loc="upper left", fontsize=9)
    fig.tight_layout()
    for ext in ("png", "svg"):
        fig.savefig(os.path.join(out, f"fig_corridor_cache.{ext}"), dpi=300)
    plt.close(fig)


def main():
    ap = ts._build_parser()
    ap.description = "多路口綠波廊道與快取機制效率模擬"
    ap.set_defaults(trials=500, envs="none,mid,high")
    ap.add_argument("--intersections", type=int, default=4, help="路口數 (1~4，對應 RSU 1~4，預設 4)")
    ap.add_argument("--first-distance", type=float, default=300.0, help="起點距第 1 個路口 (公尺，預設 300)")
    ap.add_argument("--spacing", default="300,600,900", help="路口間距 (公尺，逗號分隔；第一個值為基準)")
    ap.add_argument("--dwell", default="0,30,60", help="通過路口 1 後路段停等秒數 (逗號分隔)")
    ap.add_argument("--mode", choices=["none", "dup", "xor"], default="dup", help="冗餘模式 (預設 dup，同 OBU.main)")
    ap.add_argument("--replot", default=None, help="只依既有結果資料夾的 CSV 重畫圖表")
    args = ap.parse_args()
    if args.replot:
        def load(name, headers):
            back = {v: k for k, v in headers.items()}
            with open(os.path.join(args.replot, name), newline="", encoding="utf-8-sig") as f:
                return [{back[k]: (v if back[k] in ("env", "strategy") or v == "" else float(v)) for k, v in r.items()}
                        for r in csv.DictReader(f)]
        summary, per_int = load("corridor_summary.csv", SUMMARY_HEADERS), load("corridor_by_intersection.csv", BY_INT_HEADERS)
        for r in per_int:
            r["intersection"] = int(r["intersection"])
        _plot(summary, per_int, args.replot, float(args.spacing.split(",")[0]))
        return
    out = args.out or ts._next_run_dir()
    os.makedirs(out, exist_ok=True)
    # 衍生參數同 sim.trip_sim._resolve_args
    args.speed_mps = args.speed / 3.6
    args.ber       = ts._kv_floats(args.ber, ts.DEFAULT_BER_REF)
    args.queue_ms  = ts._kv_floats(args.queue_ms, ts.DEFAULT_QUEUE_MS)
    with contextlib.redirect_stdout(io.StringIO()):
        costs_ms = ts.calibrate() if args.calibrate else dict(ts.DEFAULT_COSTS_MS)
    costs_ms = ts._kv_floats(args.costs_ms, costs_ms)
    spacings = [float(x) for x in args.spacing.split(",")]
    dwells = [float(x) for x in args.dwell.split(",")]
    base = spacings[0]
    envs = args.envs.split(",")
    combos = {(e, base, 0.0) for e in envs}
    combos |= {("mid", s, 0.0) for s in spacings}
    combos |= {("mid", base, d) for d in dwells}
    tasks = [(args, e, s, d, st) for e, s, d in sorted(combos) for st in STRATEGIES]

    t0 = _real_time.perf_counter()
    print(f"共 {len(tasks)} 組，每組 {args.trials} 趟 …", file=sys.stderr)
    with ProcessPoolExecutor(max_workers=args.jobs, initializer=_init, initargs=(costs_ms,)) as ex:
        rows = [r for part in ex.map(run_config, tasks) for r in part]
    elapsed = _real_time.perf_counter() - t0

    summary, per_int = summarize(rows, args.intersections)
    order = lambda r: (r["env"], r["spacing_m"], r["dwell_s"], STRATEGIES.index(r["strategy"]))
    summary.sort(key=order)
    per_int.sort(key=lambda r: order(r) + (r["intersection"],))
    _write(os.path.join(out, "corridor_summary.csv"), summary, SUMMARY_HEADERS)
    _write(os.path.join(out, "corridor_by_intersection.csv"), per_int, BY_INT_HEADERS)
    _write(os.path.join(out, "corridor_trials.csv"), rows, TRIAL_HEADERS)
    _plot(summary, per_int, out, base)

    params = {
        "command": " ".join(["python3 -m sim.corridor_sim", *sys.argv[1:]]),
        "git_commit": ts._git_commit(), "run_at": _real_time.strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed_s": round(elapsed, 1), "pqc_alg": pki.pqc_alg(),
        **{k: v for k, v in vars(args).items() if k not in ("ber", "queue_ms", "costs_ms", "calibrate")},
        "loss_model": "iid", "ber_ref": args.ber, "queue_ms": args.queue_ms,
        "costs_ms": {k: round(v, 4) for k, v in costs_ms.items()}, "calibrated": args.calibrate,
        "strategies": STRATEGY_LABEL,
        "topology": "1 -> [2, 3], 2 -> [3], 3 -> [4] (RSU.main.DOWNSTREAM_TOPOLOGY)",
        "ttl_formulas": {"prewarm_old": "300 / speed + 30 s；OBU 白名單固定 60 s",
                         "prewarm": "distance / speed * 2 + 30 s；OBU 依 SSM prewarm_ttl_s"},
    }
    with open(os.path.join(out, "params.json"), "w", encoding="utf-8") as f:
        json.dump(params, f, ensure_ascii=False, indent=2)
    print(f"完成 ({elapsed:.1f}s)，輸出至 {out}/", file=sys.stderr)


if __name__ == "__main__":
    main()
