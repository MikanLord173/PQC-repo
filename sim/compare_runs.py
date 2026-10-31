"""
舊版 (安全修正 F-1~F-7 之前) 與新版實驗結果比對

讀取 sim/results/ 底下的三組成對資料夾，輸出逐項比對 (舊版、新版、差值、變化幅度)：
  1_old -> 1   trip_sim 行車模擬 (summary.csv)
  2_old -> 2   bench_compute 運算量測 (compute_summary.csv)
  3_old -> 3   poster_exp 海報實驗 (loss_sweep.csv、trip.csv、kpis.csv)

輸出 (預設 sim/results/compare_old_vs_new)：
  trip_compare.csv          行車模擬：每組 (環境, 掉包模型, 封包, 模式) 的主要指標
  compute_compare.csv       運算量測：每個項目的平均 / 中位數 / P95
  loss_sweep_compare.csv    掉包率掃描：單則訊息綠燈觸發率
  kpis_compare.csv          海報 KPI
  fig_compare_trip.png/.svg       圖 1：中掉包環境行車指標 (舊 vs 新)
  fig_compare_loss_sweep.png/.svg 圖 2：單則訊息觸發率 vs 掉包率 (舊 vs 新)
  fig_compare_compute.png/.svg    圖 3：關鍵運算耗時 (舊 vs 新)
  params.json

用法 (於專案根目錄)：
  python3 -m sim.compare_runs
"""
import argparse, csv, json, os, time

from sim.trip_sim import _git_commit
from sim.poster_exp import (_setup_matplotlib, INK, INK2, MUTED, SURFACE,
                            MODE_COLOR, MODE_LABEL, PACKET_LABEL, PACKETS, MODES)

BASE = "sim/results"
PAIRS = {"trip": ("1_old", "1"), "compute": ("2_old", "2"), "poster": ("3_old", "3")}
OLD_COLOR, NEW_COLOR = MUTED, "#2a78d6"          # 舊版中性灰、新版藍

TRIP_KEYS = ["掉包環境", "掉包模型", "封包類型", "模式"]
TRIP_METRICS = ["單則訊息大小(B)", "單則分片數", "單則傳輸量(B)", "綠燈觸發成功率(%)", "一次成功率(%)",
                "觸發耗時_平均(s)", "觸發耗時_中位數(s)", "觸發耗時_P95(s)", "嘗試次數_平均",
                "綠燈SSM端到端延遲_中位數(ms)", "閃黃燈觸發率_每則訊息(%)",
                "每次綠燈上行傳輸量_平均(B)", "每次綠燈下行SSM量_平均(B)"]
COMPUTE_METRICS = ["平均(ms)", "中位數(ms)", "P95(ms)"]
SWEEP_KEYS = ["分片掉包率_1400B(%)", "封包類型", "模式"]
SWEEP_METRICS = ["單則訊息綠燈觸發率(%)", "單則傳輸量(B)", "單則分片數"]
# 圖 3 呈現的運算項目 (項目代碼, 圖上標籤)
COMPUTE_FIG_ITEMS = [
    ("obu_gen_packet_full", "OBU 產生 Full 封包"),
    ("obu_gen_packet_short", "OBU 產生 Short 封包"),
    ("rsu_f1_verify_cold", "RSU F1 驗證 (冷)"),
    ("rsu_f1_verify_hot", "RSU F1 驗證 (熱)"),
    ("rsu_parse_packet_full", "RSU 解析 Full"),
    ("rsu_parse_packet_short", "RSU 解析 Short"),
    ("rsu_message_e2e_full_cold", "RSU 端到端 Full (冷)"),
    ("rsu_message_e2e_short_prewarmed", "RSU 端到端 Short (預熱)"),
]


def _read(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def _write(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _fmt(v):
    return "" if v is None else f"{v:.6g}"


def _diff(old, new):
    """回傳 (差值, 變化幅度%)；任一側缺值時為空，基準為 0 時幅度為空。"""
    o, n = _num(old), _num(new)
    if o is None or n is None:
        return "", ""
    return _fmt(n - o), (f"{(n - o) / o * 100:.1f}" if o else "")


def compare_table(old_rows, new_rows, keys, metrics):
    """以 keys 對齊舊新兩表，回傳長格式列：keys..., 指標, 舊版, 新版, 差值, 變化幅度(%)。
    只存在於單側的組合也會輸出 (另一側留空)。"""
    old = {tuple(r[k] for k in keys): r for r in old_rows}
    new = {tuple(r[k] for k in keys): r for r in new_rows}
    order = list(old) + [k for k in new if k not in old]
    out = []
    for key in order:
        o, n = old.get(key, {}), new.get(key, {})
        for m in metrics:
            ov, nv = o.get(m, ""), n.get(m, "")
            out.append(list(key) + [m, ov, nv, *_diff(ov, nv)])
    return out


def _lookup(rows, keys, metric):
    """把 compare_table 的輸出轉成 {(keys..., 指標): (舊, 新)}。"""
    n = len(keys)
    return {tuple(r[:n]) + (r[n],): (_num(r[n + 1]), _num(r[n + 2])) for r in rows if r[n] == metric}


# ─── 圖表 ──────────────────────────────────────────────────────────────────
def _save(fig, out, name):
    fig.tight_layout()
    for ext in ("png", "svg"):
        fig.savefig(os.path.join(out, f"{name}.{ext}"), dpi=300)


def _legend_old_new(ax, loc="lower right", **kw):
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=OLD_COLOR, label="舊版"), Patch(color=NEW_COLOR, label="新版 (F-1~F-7)")],
              loc=loc, fontsize=10, **kw)


def fig_trip(plt, trip_new_rows, trip_old_rows, out, env="mid", channel="iid"):
    pick = lambda rows: {(r["封包類型"], r["模式"]): r for r in rows
                         if r["掉包環境"] == env and r["掉包模型"] == channel}
    old, new = pick(trip_old_rows), pick(trip_new_rows)
    order = [(p, m) for p in PACKETS for m in MODES]
    labels = [f"{PACKET_LABEL[p]}+{MODE_LABEL[m]}" for p, m in order]
    panels = [("觸發耗時_平均(s)", "平均綠燈觸發時間（s）", "{:.2f}", 1),
              ("一次成功率(%)", "一次成功率（%）", "{:.0f}%", 1),
              ("單則傳輸量(B)", "單則訊息傳輸量（KB）", "{:.1f}", 1000)]
    fig, axes = plt.subplots(1, 3, figsize=(10.5, 4.4), sharey=True)
    h = 0.36
    ypos = [5.6 - i - (0.6 if i >= 3 else 0) for i in range(6)]
    for ax, (key, title, fmt, scale) in zip(axes, panels):
        ov = [float(old[k][key]) / scale for k in order]
        nv = [float(new[k][key]) / scale for k in order]
        ax.barh([y + h / 2 for y in ypos], ov, height=h, color=OLD_COLOR, zorder=3)
        ax.barh([y - h / 2 for y in ypos], nv, height=h, color=NEW_COLOR, zorder=3)
        vmax = max(ov + nv)
        for y, v in zip(ypos, nv):
            ax.text(v + vmax * 0.02, y - h / 2, fmt.format(v), va="center", fontsize=9, color=INK)
        for y, v in zip(ypos, ov):
            ax.text(v + vmax * 0.02, y + h / 2, fmt.format(v), va="center", fontsize=9, color=INK2)
        ax.set_xlim(0, vmax * 1.3)
        ax.set_title(title, loc="left", fontsize=11.5, color=INK)
        ax.grid(axis="y", visible=False)
        ax.tick_params(axis="y", length=0)
    axes[0].set_yticks(ypos, labels)
    _legend_old_new(fig, loc="upper right", ncol=2)
    fig.suptitle(f"行車模擬 舊版 vs 新版（300m、60km/h、{'中' if env == 'mid' else env}掉包環境、獨立模型，各 1000 趟）",
                 x=0.01, ha="left", fontsize=13, color=INK)
    _save(fig, out, "fig_compare_trip")
    plt.close(fig)


def fig_loss_sweep(plt, sweep_old_rows, sweep_new_rows, out):
    from matplotlib.lines import Line2D
    fig, axes = plt.subplots(1, 2, figsize=(10.5, 4.2), sharey=True)
    for ax, p in zip(axes, PACKETS):
        for rows, ls in ((sweep_old_rows, (0, (4, 3))), (sweep_new_rows, "solid")):
            for m in MODES:
                pts = sorted((float(r["分片掉包率_1400B(%)"]), float(r["單則訊息綠燈觸發率(%)"]))
                             for r in rows if r["封包類型"] == p and r["模式"] == m)
                if pts:
                    xs, ys = zip(*pts)
                    ax.plot(xs, ys, color=MODE_COLOR[m], linestyle=ls, linewidth=2, zorder=3,
                            dash_capstyle="round", solid_capstyle="round")
        ax.set_title(f"{PACKET_LABEL[p]} 封包", loc="left", fontsize=11.5, color=INK)
        ax.set_xlim(0, 50)
        ax.set_ylim(0, 102)
        ax.set_xlabel("分片掉包率（以 1400B 分片計，%）")
    axes[0].set_ylabel("單則訊息觸發綠燈機率（%）")
    mode_keys = [Line2D([], [], color=MODE_COLOR[m], linewidth=2, label=MODE_LABEL[m]) for m in MODES]
    ver_keys = [Line2D([], [], color=INK2, linewidth=2, linestyle=(0, (4, 3)), label="舊版"),
                Line2D([], [], color=INK2, linewidth=2, label="新版")]
    leg = axes[1].legend(handles=mode_keys, loc="upper right", fontsize=10, title="模式", title_fontsize=10)
    axes[1].add_artist(leg)
    axes[1].legend(handles=ver_keys, loc="upper right", bbox_to_anchor=(0.78, 1), fontsize=10,
                   title="版本", title_fontsize=10)
    fig.suptitle("單則訊息可靠度 舊版 vs 新版（Full 封包因加入 CA 後量子憑證而變大）",
                 x=0.01, ha="left", fontsize=13, color=INK)
    _save(fig, out, "fig_compare_loss_sweep")
    plt.close(fig)


def fig_compute(plt, comp_old_rows, comp_new_rows, out, liboqs):
    old = {r["項目代碼"]: float(r["平均(ms)"]) for r in comp_old_rows}
    new = {r["項目代碼"]: float(r["平均(ms)"]) for r in comp_new_rows}
    items = [(k, lab) for k, lab in COMPUTE_FIG_ITEMS if k in old and k in new]
    fig, ax = plt.subplots(figsize=(7.5, 4.6))
    h = 0.38
    ypos = list(range(len(items) - 1, -1, -1))
    ov = [old[k] for k, _ in items]
    nv = [new[k] for k, _ in items]
    ax.barh([y + h / 2 for y in ypos], ov, height=h, color=OLD_COLOR, zorder=3)
    ax.barh([y - h / 2 for y in ypos], nv, height=h, color=NEW_COLOR, zorder=3)
    vmax = max(ov + nv)
    for y, v in zip(ypos, ov):
        ax.text(v + vmax * 0.015, y + h / 2, f"{v:.2f}", va="center", fontsize=9, color=INK2)
    for y, v in zip(ypos, nv):
        ax.text(v + vmax * 0.015, y - h / 2, f"{v:.2f}", va="center", fontsize=9, color=INK)
    ax.set_xlim(0, vmax * 1.18)
    ax.set_yticks(ypos, [lab for _, lab in items])
    ax.set_xlabel("平均耗時（ms，1000 次）")
    ax.grid(axis="y", visible=False)
    ax.tick_params(axis="y", length=0)
    _legend_old_new(ax)
    ax.set_title(f"關鍵運算耗時 舊版 vs 新版（liboqs {liboqs[0]} → {liboqs[1]}）",
                 loc="left", fontsize=13, color=INK, pad=10)
    _save(fig, out, "fig_compare_compute")
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser(description="比對 sim/results 舊版 (*_old) 與新版實驗結果")
    ap.add_argument("--out", default=os.path.join(BASE, "compare_old_vs_new"), help="輸出目錄")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    path = lambda run, name: os.path.join(BASE, run, name)
    cols = ["指標", "舊版", "新版", "差值", "變化幅度(%)"]

    # 1. 行車模擬
    t_old, t_new = (_read(path(r, "summary.csv")) for r in PAIRS["trip"])
    trip = compare_table(t_old, t_new, TRIP_KEYS, TRIP_METRICS)
    _write(os.path.join(args.out, "trip_compare.csv"), TRIP_KEYS + cols, trip)

    # 2. 運算量測
    c_old, c_new = (_read(path(r, "compute_summary.csv")) for r in PAIRS["compute"])
    comp = compare_table(c_old, c_new, ["項目代碼"], COMPUTE_METRICS)
    desc = {r["項目代碼"]: (r["項目說明"], r["分類"]) for r in c_old + c_new}
    comp = [[r[0], *desc[r[0]], *r[1:]] for r in comp]
    _write(os.path.join(args.out, "compute_compare.csv"), ["項目代碼", "項目說明", "分類"] + cols, comp)

    # 3. 海報實驗
    s_old, s_new = (_read(path(r, "loss_sweep.csv")) for r in PAIRS["poster"])
    sweep = compare_table(s_old, s_new, SWEEP_KEYS, SWEEP_METRICS)
    _write(os.path.join(args.out, "loss_sweep_compare.csv"), SWEEP_KEYS + cols, sweep)

    k_old, k_new = (_read(path(r, "kpis.csv")) for r in PAIRS["poster"])
    k_key = lambda r: (r["指標"], r["比較 (基準 -> 對照)"].split(" (run")[0])   # KPI 標籤含 run 編號，比對時去除
    kold = {k_key(r): r for r in k_old}
    kpis = []
    for r in k_new:
        o = kold.get(k_key(r), {})
        for side in ("基準值", "對照值"):
            kpis.append([r["指標"], k_key(r)[1], side, r["單位"], o.get(side, ""), r[side], *_diff(o.get(side), r[side])])
        kpis.append([r["指標"], k_key(r)[1], "變化幅度(%)", "%", o.get("變化幅度(%)", ""), r["變化幅度(%)"],
                     *_diff(o.get("變化幅度(%)"), r["變化幅度(%)"])])
    _write(os.path.join(args.out, "kpis_compare.csv"),
           ["指標", "比較 (基準 -> 對照)", "欄位", "單位", "舊版", "新版", "差值", "變化幅度(%)"], kpis)

    # 圖表
    liboqs = tuple(json.load(open(path(r, "params.json"))).get("liboqs", "?") for r in PAIRS["compute"])
    plt = _setup_matplotlib()
    fig_trip(plt, t_new, t_old, args.out)
    fig_loss_sweep(plt, s_old, s_new, args.out)
    fig_compute(plt, c_old, c_new, args.out, liboqs)

    params = {
        "command": "python3 -m sim.compare_runs",
        "git_commit": _git_commit(),
        "run_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "out": args.out,
        "pairs": {name: {"old": os.path.join(BASE, o), "new": os.path.join(BASE, n)} for name, (o, n) in PAIRS.items()},
        "source_commits": {run: json.load(open(path(run, "params.json"))).get("git_commit", "")
                           for pair in PAIRS.values() for run in pair},
        "liboqs": {"old": liboqs[0], "new": liboqs[1]},
        "notes": [
            "新版 = 安全修正 F-1~F-7 後 (commit f627e72)；舊版 = 修正前",
            "Full 封包加入 CA ML-DSA-44 憑證 (約 +2.4KB)，F1 加入角色與 H(sig_PQC)，SSM 加入 RSU 簽章與憑證",
            "運算量測的差異同時包含程式修改與 liboqs 版本變更 (見 liboqs 欄位)",
        ],
    }
    with open(os.path.join(args.out, "params.json"), "w", encoding="utf-8") as f:
        json.dump(params, f, ensure_ascii=False, indent=2)
    print(f"已輸出至 {args.out}")


if __name__ == "__main__":
    main()
