"""
海報用實驗：呈現 Short 封包與 DUP / XOR 冗餘模式的優化成果

實驗 A ─ 掉包率掃描 (單則訊息可靠度)
  固定 BER (α = 0，與距離無關)，以「1400B MTU 分片的掉包率」為橫軸 0%~50% 掃描，
  每點每組 1000 則訊息，量測「單則訊息直接觸發綠燈」的機率。
  BER 由 PER_ref 反推：BER = 1 - (1 - PER_ref)^(1 / (8·(1400 + 64)))，
  同一 BER 下較小的分片 (Short 封包、XOR 的 607B F1) 掉包率自然較低。
  車輛設定為 1 秒內抵達 (距離 10m、36km/h)，每趟恰好只送一則訊息，故成功率 = 單則訊息成功率。

實驗 B ─ 實際行車 (多次重試)
  與第 1 組實驗相同情境 (300m、60km/h、間隔 1s)，中/高掉包環境 (獨立模型)，每組 1000 趟。

輸出 (預設 sim/results/ 底下下一個未使用的編號資料夾)：
  loss_sweep.csv      實驗 A 結果
  trip.csv            實驗 B 彙總
  kpis.csv            海報重點數據 (基準 vs 本系統，含改善幅度)
  fig_loss_sweep.png/.svg   圖 1：單則訊息綠燈觸發率 vs 分片掉包率
  fig_trip.png/.svg         圖 2：實際行車三項指標 (中掉包環境)
  params.json

用法 (於專案根目錄)：
  python3 -m sim.poster_exp
"""
import argparse, csv, json, math, os, sys, time
from concurrent.futures import ProcessPoolExecutor

from sim.trip_sim import (_resolve_args, _init_worker, _run_config, _summarize, _message_samples,
                          _next_run_dir, _git_commit, LINK_OVERHEAD, GE_REF_SIZE)

PACKETS = ("full", "short")
MODES   = ("none", "dup", "xor")
PER_GRID = [i * 5 for i in range(11)]            # 1400B 分片掉包率 0%, 5%, ..., 50%

# ─── 圖表配色 (dataviz 參考調色盤，已通過 CVD 驗證) ──────────────────────────
INK, INK2, MUTED = "#0b0b0b", "#52514e", "#898781"
GRID, AXIS, SURFACE = "#e1e0d9", "#c3c2b7", "#fcfcfb"
MODE_COLOR = {"none": MUTED, "dup": "#2a78d6", "xor": "#eb6834"}   # 基準為中性灰，DUP 藍、XOR 橘
MODE_LABEL = {"none": "None", "dup": "DUP", "xor": "XOR"}
PACKET_LABEL = {"full": "Full", "short": "Short"}
PACKET_STYLE = {"full": (0, (4, 3)), "short": "solid"}               # Full 虛線、Short 實線


def per_to_ber(per_pct):
    bits = 8 * (GE_REF_SIZE + LINK_OVERHEAD)
    return 1.0 - (1.0 - per_pct / 100.0) ** (1.0 / bits)


def ci95(p, n):
    """二項比例 95% 信賴區間半寬 (常態近似，單位：百分點)。"""
    return 1.96 * math.sqrt(p * (1 - p) / n) * 100 if n else 0.0


def _write_csv(path, rows, headers):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(headers.values())
        for r in rows:
            w.writerow(r[k] for k in headers)


# ─── 實驗 ──────────────────────────────────────────────────────────────────
def build_tasks(trials, seed):
    envs  = [f"p{p:02d}" for p in PER_GRID]
    ber   = ",".join(f"{e}={per_to_ber(p):.6e}" for e, p in zip(envs, PER_GRID))
    queue = ",".join(f"{e}=0.5" for e in envs)
    sweep_args, costs = _resolve_args(["--distance", "10", "--speed", "36", "--interval", "1", "--alpha", "0",
                                       "--trials", str(trials), "--seed", str(seed), "--envs", ",".join(envs),
                                       "--ber", ber, "--queue-ms", queue, "--out", "-"])
    trip_args, _ = _resolve_args(["--trials", str(trials), "--seed", str(seed), "--envs", "mid,high", "--out", "-"])
    tasks  = [(sweep_args, e, "iid", p, m) for e in envs for p in PACKETS for m in MODES]
    tasks += [(trip_args, e, "iid", p, m) for e in ("mid", "high") for p in PACKETS for m in MODES]
    return tasks, sweep_args, trip_args, costs


def run(tasks, costs, jobs):
    results = {}
    with ProcessPoolExecutor(max_workers=jobs, initializer=_init_worker, initargs=(costs,)) as ex:
        for task, rows in zip(tasks, ex.map(_run_config, tasks)):
            results[(id(task[0]),) + task[1:]] = rows
            print(f"  {task[1]:<4} {task[3]:<5} {task[4]:<4} 成功率 "
                  f"{100 * sum(r['success'] for r in rows) / len(rows):6.2f}%", file=sys.stderr)
    return results


# ─── 圖表 ──────────────────────────────────────────────────────────────────
def _setup_matplotlib():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib import font_manager as fm
    for path in ("/System/Library/Fonts/STHeiti Medium.ttc", "/System/Library/Fonts/STHeiti Light.ttc"):
        if os.path.exists(path):
            fm.fontManager.addfont(path)
    plt.rcParams.update({
        "font.family": ["Heiti TC", "sans-serif"],     # macOS 內建繁中字型 (STHeiti)
        "axes.unicode_minus": False, "font.size": 11,
        "axes.edgecolor": AXIS, "axes.linewidth": 1, "axes.labelcolor": INK2,
        "xtick.color": MUTED, "ytick.color": MUTED, "xtick.labelcolor": INK2, "ytick.labelcolor": INK2,
        "axes.grid": True, "grid.color": GRID, "grid.linewidth": 1, "grid.linestyle": "-",
        "axes.spines.top": False, "axes.spines.right": False,
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "text.color": INK, "legend.frameon": False,
    })
    return plt


def fig_loss_sweep(plt, sweep_rows, out):
    from matplotlib.lines import Line2D
    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    series = {}
    for r in sweep_rows:
        series.setdefault((r["packet"], r["mode"]), []).append((r["per_ref_pct"], r["success_pct"]))
    for (p, m), pts in series.items():
        pts.sort()
        xs, ys = zip(*pts)
        ax.plot(xs, ys, color=MODE_COLOR[m], linestyle=PACKET_STYLE[p], linewidth=2,
                solid_capstyle="round", dash_capstyle="round", zorder=3)
        ax.plot(xs, ys, "o", color=MODE_COLOR[m], markersize=5.5, markeredgecolor=SURFACE,
                markeredgewidth=1.5, zorder=4)

    # 只標兩條故事主線的端點：最差 (Full/None) 與最佳 (Short/XOR)
    for (p, m) in (("full", "none"), ("short", "xor")):
        x, y = max(series[(p, m)])
        ax.annotate(f"{PACKET_LABEL[p]}+{MODE_LABEL[m]}  {y:.0f}%", (x, y), xytext=(6, 0),
                    textcoords="offset points", va="center", fontsize=10, color=INK)

    ax.set_xlim(0, 58)
    ax.set_ylim(0, 102)
    ax.set_xticks(PER_GRID[::2])
    ax.set_xlabel("分片掉包率（以 1400B 分片計，%）")
    ax.set_ylabel("單則訊息觸發綠燈機率（%）")
    ax.set_title("單則訊息可靠度：Short 與 XOR 讓訊息更耐掉包", loc="left", fontsize=13, color=INK, pad=10)

    mode_keys = [Line2D([], [], color=MODE_COLOR[m], linewidth=2, marker="o", markersize=5.5,
                        markeredgecolor=SURFACE, label=MODE_LABEL[m]) for m in MODES]
    pkt_keys = [Line2D([], [], color=INK2, linewidth=2, linestyle=PACKET_STYLE[p], label=PACKET_LABEL[p] + " 封包")
                for p in PACKETS]
    leg1 = ax.legend(handles=mode_keys, loc="lower left", fontsize=10, title="模式", title_fontsize=10)
    ax.add_artist(leg1)
    ax.legend(handles=pkt_keys, loc="lower left", bbox_to_anchor=(0.2, 0), fontsize=10, title="封包", title_fontsize=10)
    fig.tight_layout()
    for ext in ("png", "svg"):
        fig.savefig(os.path.join(out, f"fig_loss_sweep.{ext}"), dpi=300)
    plt.close(fig)


def fig_trip(plt, trip_rows, out, env="mid"):
    rows = {(r["packet"], r["mode"]): r for r in trip_rows if r["env"] == env}
    order = [(p, m) for p in PACKETS for m in MODES]
    labels = [f"{PACKET_LABEL[p]}+{MODE_LABEL[m]}" for p, m in order]
    panels = [
        ("ttg_mean_s", "平均綠燈觸發時間（s）", lambda v: f"{v:.2f}"),
        ("first_try_rate_pct", "一次成功率（%）", lambda v: f"{v:.0f}%"),
        ("bytes_up_mean", "每次綠燈總傳輸量（KB）", lambda v: f"{v / 1000:.1f}"),
    ]
    fig, axes = plt.subplots(1, 3, figsize=(10, 3.6), sharey=True)
    ypos = [5.6 - i - (0.6 if i >= 3 else 0) for i in range(6)]          # Full 與 Short 兩組之間留白
    for ax, (key, title, fmt) in zip(axes, panels):
        vals = [float(rows[k][key]) / (1000 if key == "bytes_up_mean" else 1) for k in order]
        ax.barh(ypos, vals, height=0.62, color=[MODE_COLOR[m] for _, m in order], zorder=3)
        vmax = max(vals)
        for y, v in zip(ypos, vals):
            ax.text(v + vmax * 0.02, y, fmt(v * (1000 if key == "bytes_up_mean" else 1)),
                    va="center", fontsize=10, color=INK)
        ax.set_xlim(0, vmax * 1.28)
        ax.set_title(title, loc="left", fontsize=11.5, color=INK)
        ax.grid(axis="y", visible=False)
        ax.tick_params(axis="y", length=0)
    axes[0].set_yticks(ypos, labels)
    fig.suptitle("實際行車（300m、60km/h、中掉包環境，各 1000 趟）", x=0.01, ha="left", fontsize=13, color=INK)
    fig.tight_layout()
    for ext in ("png", "svg"):
        fig.savefig(os.path.join(out, f"fig_trip.{ext}"), dpi=300)
    plt.close(fig)


# ─── KPI ───────────────────────────────────────────────────────────────────
def _latest_compute_csv():
    """sim/results/ 底下編號最大、含 compute_summary.csv 的資料夾 (bench_compute 的最新結果)。"""
    runs = [d for d in os.listdir("sim/results") if d.isdigit()
            and os.path.exists(os.path.join("sim/results", d, "compute_summary.csv"))]
    return os.path.join("sim/results", max(runs, key=int), "compute_summary.csv") if runs else None


def build_kpis(sweep_rows, trip_rows, samples, compute_csv=None):
    sw   = {(r["per_ref_pct"], r["packet"], r["mode"]): r for r in sweep_rows}
    trip = {(r["env"], r["packet"], r["mode"]): r for r in trip_rows}
    kpis = []

    def add(metric, compare, base, new, unit, better="lower"):
        change = (new - base) / base * 100 if base else float("nan")
        kpis.append({"metric": metric, "compare": compare, "base": round(base, 4), "new": round(new, 4),
                     "unit": unit, "change_pct": round(change, 1),
                     "abs_change": round(new - base, 4)})

    f, s = samples[("full", "none")], samples[("short", "none")]
    add("udp_bytes_per_msg", "full/none -> short/none", f["udp_bytes"], s["udp_bytes"], "B")
    add("fragments_per_msg", "full/none -> short/none", f["frags"], s["frags"], "frags")
    for per in (20, 40):
        for comp in (("full", "none", "full", "dup"), ("full", "none", "full", "xor"),
                     ("full", "none", "short", "none"), ("full", "none", "short", "xor")):
            a, b = sw[(per, comp[0], comp[1])], sw[(per, comp[2], comp[3])]
            add(f"single_msg_success_at_per{per}", f"{comp[0]}/{comp[1]} -> {comp[2]}/{comp[3]}",
                a["success_pct"], b["success_pct"], "%", "higher")
    for env in ("mid", "high"):
        for comp in (("full", "none", "full", "dup"), ("full", "none", "full", "xor"),
                     ("full", "none", "short", "none"), ("full", "none", "short", "xor")):
            a, b = trip[(env, comp[0], comp[1])], trip[(env, comp[2], comp[3])]
            tag = f"{comp[0]}/{comp[1]} -> {comp[2]}/{comp[3]}"
            add(f"{env}_ttg_mean_s", tag, a["ttg_mean_s"], b["ttg_mean_s"], "s")
            add(f"{env}_ttg_p95_s", tag, a["ttg_p95_s"], b["ttg_p95_s"], "s")
            add(f"{env}_first_try_pct", tag, a["first_try_rate_pct"], b["first_try_rate_pct"], "%", "higher")
            add(f"{env}_attempts_mean", tag, a["attempts_mean"], b["attempts_mean"], "times")
            add(f"{env}_bytes_per_green", tag, a["bytes_up_mean"], b["bytes_up_mean"], "B")
    if compute_csv and os.path.exists(compute_csv):
        with open(compute_csv, encoding="utf-8-sig") as fh:
            c = {r["項目代碼"]: float(r["平均(ms)"]) for r in csv.DictReader(fh)}
        run_no = os.path.basename(os.path.dirname(compute_csv))
        add("rsu_compute_per_msg_ms", f"full cold -> short prewarmed (run {run_no})",
            c["rsu_message_e2e_full_cold"], c["rsu_message_e2e_short_prewarmed"], "ms")
    return kpis


SWEEP_HEADERS = {"per_ref_pct": "分片掉包率_1400B(%)", "ber": "BER", "packet": "封包類型", "mode": "模式",
                 "trials": "訊息數", "success_pct": "單則訊息綠燈觸發率(%)", "success_ci95": "95%信賴區間半寬(百分點)",
                 "flash_pct": "閃黃燈率(%)", "udp_bytes_per_msg": "單則傳輸量(B)", "frags_per_msg": "單則分片數"}
TRIP_HEADERS = {"env": "掉包環境", "packet": "封包類型", "mode": "模式", "trials": "趟次數",
                "success_rate_pct": "綠燈觸發成功率(%)", "first_try_rate_pct": "一次成功率(%)",
                "ttg_mean_s": "觸發耗時_平均(s)", "ttg_p50_s": "觸發耗時_中位數(s)", "ttg_p95_s": "觸發耗時_P95(s)",
                "attempts_mean": "嘗試次數_平均", "e2e_p50_ms": "綠燈SSM端到端延遲_中位數(ms)",
                "bytes_up_mean": "每次綠燈上行傳輸量_平均(B)", "udp_bytes_per_msg": "單則傳輸量(B)",
                "frags_per_msg": "單則分片數"}
KPI_HEADERS = {"metric": "指標", "compare": "比較 (基準 -> 對照)", "base": "基準值", "new": "對照值",
               "unit": "單位", "abs_change": "差值", "change_pct": "變化幅度(%)"}


def main():
    ap = argparse.ArgumentParser(description="海報用實驗：Short 封包與 DUP / XOR 優化成果")
    ap.add_argument("--trials", type=int, default=1000, help="每組趟次 / 訊息數 (預設 1000)")
    ap.add_argument("--seed", type=int, default=42, help="固定亂數種子 (預設 42)")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1, help="平行行程數")
    ap.add_argument("--out", default=None, help="輸出目錄 (預設為 sim/results/ 底下下一個未使用的編號資料夾)")
    args = ap.parse_args()
    out = args.out or _next_run_dir()
    os.makedirs(out, exist_ok=True)

    t0 = time.perf_counter()
    tasks, sweep_args, trip_args, costs = build_tasks(args.trials, args.seed)
    results = run(tasks, costs, args.jobs)
    samples = _message_samples()

    sweep_rows, trip_rows = [], []
    for task in tasks:
        a, env, ch, p, m = task
        rows = results[(id(a), env, ch, p, m)]
        if a is sweep_args:
            per = int(env[1:])
            ok = sum(r["success"] for r in rows) / len(rows)
            sweep_rows.append({"per_ref_pct": per, "ber": f"{per_to_ber(per):.3e}", "packet": p, "mode": m,
                               "trials": len(rows), "success_pct": round(ok * 100, 2),
                               "success_ci95": round(ci95(ok, len(rows)), 2),
                               "flash_pct": round(100 * sum(r["flash_any"] for r in rows) / len(rows), 2),
                               "udp_bytes_per_msg": samples[(p, m)]["udp_bytes"], "frags_per_msg": samples[(p, m)]["frags"]})
        else:
            trip_rows.append(_summarize(trip_args, {"env": env, "channel": ch, "packet": p, "mode": m},
                                        rows, samples[(p, m)]))

    compute_csv = _latest_compute_csv()
    kpis = build_kpis(sweep_rows, trip_rows, samples, compute_csv)
    _write_csv(os.path.join(out, "loss_sweep.csv"), sweep_rows, SWEEP_HEADERS)
    _write_csv(os.path.join(out, "trip.csv"), trip_rows, TRIP_HEADERS)
    _write_csv(os.path.join(out, "kpis.csv"), kpis, KPI_HEADERS)

    plt = _setup_matplotlib()
    fig_loss_sweep(plt, sweep_rows, out)
    fig_trip(plt, trip_rows, out)

    elapsed = time.perf_counter() - t0
    params = {
        "command": " ".join(["python3 -m sim.poster_exp", *sys.argv[1:]]),
        "git_commit": _git_commit(), "run_at": time.strftime("%Y-%m-%d %H:%M:%S"), "elapsed_s": round(elapsed, 1),
        "trials": args.trials, "seed": args.seed,
        "exp_a_loss_sweep": {"per_ref_pct_grid": PER_GRID, "ref_fragment_bytes": GE_REF_SIZE,
                             "ber_from_per": "BER = 1 - (1 - PER)^(1/(8*(1400+64)))",
                             "distance_m": sweep_args.distance, "speed_kmh": sweep_args.speed,
                             "alpha": sweep_args.alpha, "queue_ms": 0.5, "loss_model": "iid",
                             "note": "one message per trial (arrival within 1 s)"},
        "exp_b_trip": {"distance_m": trip_args.distance, "speed_kmh": trip_args.speed,
                       "interval_s": trip_args.interval, "envs": ["mid", "high"], "ber_ref": trip_args.ber,
                       "queue_ms": trip_args.queue_ms, "alpha": trip_args.alpha, "d_ref": trip_args.d_ref,
                       "loss_model": "iid"},
        "costs_ms": costs,
        "compute_kpi_source": compute_csv,
    }
    with open(os.path.join(out, "params.json"), "w", encoding="utf-8") as f:
        json.dump(params, f, ensure_ascii=False, indent=2)
    print(f"完成 ({elapsed:.1f}s)，輸出至 {out}/", file=sys.stderr)


if __name__ == "__main__":
    main()
