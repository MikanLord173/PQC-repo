"""
後量子簽章演算法對照：ML-DSA-44 (預設) vs Falcon-512

每個演算法在獨立的暫存工作目錄 (tempfile) 以 sim.provision 佈建全新 CA / RSU / OBU 金鑰，
再執行同一組實驗，不會動到專案根目錄現有金鑰：
  1. sim.bench_compute   運算耗時微基準 (--iterations)
  2. sim.trip_sim        單一路口行車模擬 (--calibrate：運算耗時改用該演算法的本機實測值)

輸出 (預設 sim/results/ 底下下一個未使用的編號資料夾)：
  <alg>/compute/…、<alg>/trip/…   各演算法的原始實驗結果 (格式同 bench_compute / trip_sim)
  pqc_sizes.csv            金鑰 / 簽章 / 封包大小與分片數
  pqc_compute.csv          關鍵運算耗時對照
  pqc_trip.csv             行車模擬主要指標對照
  fig_pqc_compare.png/.svg 圖：封包大小、觸發時間、RSU 運算耗時
  params.json

用法 (於專案根目錄)：
  python3 -m sim.pqc_compare
"""
import argparse, csv, json, os, shutil, subprocess, sys, tempfile, time

from sim.trip_sim import _next_run_dir, _git_commit

ALGS = ("ML-DSA-44", "Falcon-512")
ALG_COLOR = {"ML-DSA-44": "#898781", "Falcon-512": "#2a78d6"}
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

COMPUTE_ITEMS = [
    ("obu_mldsa_sign", "OBU 後量子簽章"),
    ("rsu_mldsa_verify", "RSU 後量子驗簽"),
    ("obu_gen_packet_full", "OBU 產生 Full 封包"),
    ("obu_gen_packet_short", "OBU 產生 Short 封包"),
    ("rsu_parse_packet_full", "RSU 解析 Full"),
    ("rsu_parse_packet_short", "RSU 解析 Short"),
    ("rsu_message_e2e_full_cold", "RSU 端到端 Full (冷)"),
    ("rsu_message_e2e_short_prewarmed", "RSU 端到端 Short (預熱)"),
]
TRIP_METRICS = ["單則訊息大小(B)", "單則分片數", "單則傳輸量(B)", "綠燈觸發成功率(%)", "一次成功率(%)",
                "觸發耗時_平均(s)", "觸發耗時_P95(s)", "嘗試次數_平均", "綠燈SSM端到端延遲_中位數(ms)",
                "每次綠燈上行傳輸量_平均(B)"]


def _read(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def _write(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def _pct_change(a, b):
    try:
        a, b = float(a), float(b)
        return f"{(b - a) / a * 100:.1f}" if a else ""
    except ValueError:
        return ""


def run_alg(alg, out, args):
    """在暫存目錄佈建 alg 的金鑰並執行實驗，結果寫入 out/<alg>/。"""
    env = dict(os.environ, PQC_SIG_ALG=alg, PYTHONPATH=ROOT,
               GIT_DIR=os.path.join(ROOT, ".git"), GIT_WORK_TREE=ROOT)   # 讓 params.json 的 git_commit 指向本專案
    dest = os.path.join(out, alg)
    ws = tempfile.mkdtemp(prefix=f"pqc_{alg}_")
    py = sys.executable
    try:
        steps = [
            [py, "-m", "sim.provision", "--dir", ws],
            [py, "-m", "sim.bench_compute", "--iterations", str(args.iterations), "--out", os.path.join(dest, "compute")],
            [py, "-m", "sim.trip_sim", "--calibrate", "--trials", str(args.trials), "--envs", args.envs,
             "--channels", "iid", "--jobs", str(args.jobs), "--out", os.path.join(dest, "trip")],
        ]
        for cmd in steps:
            print(f"[{alg}] {' '.join(cmd[2:4])} …", file=sys.stderr)
            subprocess.run(cmd, cwd=ws, env=env, check=True, stdout=subprocess.DEVNULL)
        sizes = subprocess.run([py, "-c", _SIZE_PROBE], cwd=ws, env=env, check=True,
                               capture_output=True, text=True).stdout
        return json.loads(sizes.strip().splitlines()[-1])
    finally:
        shutil.rmtree(ws, ignore_errors=True)


# 在佈建好的工作目錄量測金鑰 / 簽章 / 封包大小 (每種封包取 200 則平均，Falcon 簽章長度不固定)
_SIZE_PROBE = r"""
import contextlib, io, json, statistics, oqs, pki
from OBU.encode_packet import gen_packet, load_cert
from OBU.fragment import make_fragments
from fec import make_fragments_xor
d = oqs.Signature(pki.pqc_alg()).details
P_U, role, pub, cert = load_cert("AMB-217")
res = {"alg": pki.pqc_alg(), "nist_level": d["claimed_nist_level"], "pk": d["length_public_key"],
       "sk": d["length_secret_key"], "sig_max": d["length_signature"], "ca_cert": len(cert)}
for kind, short in (("full", False), ("short", True)):
    lens, nfr, nxor = [], [], []
    with contextlib.redirect_stdout(io.StringIO()):
        for i in range(200):
            p = gen_packet("AMB-217", known_RSU=short)
            lens.append(len(p)); nfr.append(len(make_fragments(p, 1)))
            data, par = make_fragments_xor(p, 1); nxor.append(len(data) + (par is not None))
    res[kind] = {"bytes_mean": round(statistics.fmean(lens), 1), "bytes_max": max(lens),
                 "frags": round(statistics.fmean(nfr), 2), "frags_max": max(nfr),
                 "frags_xor": round(statistics.fmean(nxor), 2)}
print(json.dumps(res))
"""


def _plot(sizes, comp, trip, out, env):
    from sim.poster_exp import _setup_matplotlib, INK
    plt = _setup_matplotlib()
    fig, axes = plt.subplots(1, 3, figsize=(12, 3.9))
    w = 0.36

    # (a) 封包大小
    cats = [("full", "Full 封包"), ("short", "Short 封包")]
    for k, alg in enumerate(ALGS):
        xs = [i + (k - 0.5) * w for i in range(len(cats))]
        ys = [sizes[alg][c]["bytes_mean"] / 1000 for c, _ in cats]
        axes[0].bar(xs, ys, width=w, color=ALG_COLOR[alg], label=alg, zorder=3)
        for x, (c, _), y in zip(xs, cats, ys):
            axes[0].text(x, y, f"{y:.1f}KB\n{sizes[alg][c]['frags']:g}片", ha="center", va="bottom", fontsize=8.5, color=INK)
    axes[0].set_xticks(range(len(cats)), [c[1] for c in cats])
    axes[0].set_ylim(0, max(sizes[a]["full"]["bytes_mean"] for a in ALGS) / 1000 * 1.3)
    axes[0].set_title("單則訊息大小 (KB) 與分片數", loc="left", fontsize=11, color=INK)

    # (b) 中掉包環境平均觸發時間
    combos = [("full", "none"), ("full", "xor"), ("short", "none"), ("short", "xor")]
    for k, alg in enumerate(ALGS):
        xs = [i + (k - 0.5) * w for i in range(len(combos))]
        ys = [float(trip[alg][(env, p, m)]["觸發耗時_平均(s)"]) for p, m in combos]
        axes[1].bar(xs, ys, width=w, color=ALG_COLOR[alg], zorder=3)
        for x, y in zip(xs, ys):
            axes[1].text(x, y, f"{y:.2f}", ha="center", va="bottom", fontsize=8.5, color=INK)
    axes[1].set_xticks(range(len(combos)), [f"{p.capitalize()}+{m.upper() if m != 'none' else 'None'}" for p, m in combos])
    axes[1].set_title(f"平均綠燈觸發時間 (s)，{'中' if env == 'mid' else env}掉包環境", loc="left", fontsize=11, color=INK)

    # (c) 運算耗時
    items = [("obu_mldsa_sign", "PQC 簽章"), ("rsu_mldsa_verify", "PQC 驗簽"),
             ("rsu_message_e2e_full_cold", "RSU 端到端\nFull"), ("rsu_message_e2e_short_prewarmed", "RSU 端到端\nShort")]
    for k, alg in enumerate(ALGS):
        xs = [i + (k - 0.5) * w for i in range(len(items))]
        ys = [comp[alg][c] for c, _ in items]
        axes[2].bar(xs, ys, width=w, color=ALG_COLOR[alg], zorder=3)
        for x, y in zip(xs, ys):
            axes[2].text(x, y, f"{y:.2f}", ha="center", va="bottom", fontsize=8.5, color=INK)
    axes[2].set_xticks(range(len(items)), [lab for _, lab in items], fontsize=9)
    axes[2].set_title("運算耗時 (ms，平均)", loc="left", fontsize=11, color=INK)
    for ax in axes:
        ax.grid(axis="x", visible=False)
    axes[0].legend(loc="upper right", fontsize=9)
    fig.tight_layout()
    for ext in ("png", "svg"):
        fig.savefig(os.path.join(out, f"fig_pqc_compare.{ext}"), dpi=300)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser(description="ML-DSA-44 vs Falcon-512 對照實驗")
    ap.add_argument("--iterations", type=int, default=1000, help="bench_compute 每項量測次數")
    ap.add_argument("--trials", type=int, default=1000, help="trip_sim 每組趟次")
    ap.add_argument("--envs", default="none,mid,high", help="trip_sim 掉包環境")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    out = os.path.abspath(args.out or _next_run_dir())
    os.makedirs(out, exist_ok=True)

    t0 = time.perf_counter()
    sizes = {alg: run_alg(alg, out, args) for alg in ALGS}
    elapsed = time.perf_counter() - t0

    # 大小
    rows = []
    for field, label in (("pk", "PQC 公鑰(B)"), ("sk", "PQC 私鑰(B)"), ("sig_max", "PQC 簽章上限(B)"),
                         ("ca_cert", "CA 後量子憑證(B)"), ("nist_level", "NIST 安全等級")):
        a, b = sizes[ALGS[0]][field], sizes[ALGS[1]][field]
        rows.append([label, a, b, b - a, _pct_change(a, b)])
    for kind in ("full", "short"):
        for field, label in (("bytes_mean", "訊息大小_平均(B)"), ("bytes_max", "訊息大小_最大(B)"),
                             ("frags", "分片數_平均(none/dup)"), ("frags_max", "分片數_最大(none/dup)"),
                             ("frags_xor", "分片數_平均(xor，含FP)")):
            a, b = sizes[ALGS[0]][kind][field], sizes[ALGS[1]][kind][field]
            rows.append([f"{kind.capitalize()} {label}", a, b, round(b - a, 1), _pct_change(a, b)])
    _write(os.path.join(out, "pqc_sizes.csv"), ["項目", *ALGS, "差值", "變化幅度(%)"], rows)

    # 運算
    comp = {}
    for alg in ALGS:
        comp[alg] = {r["項目代碼"]: float(r["平均(ms)"]) for r in _read(os.path.join(out, alg, "compute", "compute_summary.csv"))}
    rows = [[code, lab, f"{comp[ALGS[0]][code]:.6g}", f"{comp[ALGS[1]][code]:.6g}",
             f"{comp[ALGS[1]][code] - comp[ALGS[0]][code]:.6g}", _pct_change(comp[ALGS[0]][code], comp[ALGS[1]][code])]
            for code, lab in COMPUTE_ITEMS]
    _write(os.path.join(out, "pqc_compute.csv"), ["項目代碼", "項目", *[f"{a} 平均(ms)" for a in ALGS], "差值(ms)", "變化幅度(%)"], rows)

    # 行車
    trip = {}
    for alg in ALGS:
        trip[alg] = {(r["掉包環境"], r["封包類型"], r["模式"]): r
                     for r in _read(os.path.join(out, alg, "trip", "summary.csv"))}
    rows = []
    for key in trip[ALGS[0]]:
        for m in TRIP_METRICS:
            a, b = trip[ALGS[0]][key][m], trip[ALGS[1]][key][m]
            rows.append([*key, m, a, b, _pct_change(a, b)])
    _write(os.path.join(out, "pqc_trip.csv"), ["掉包環境", "封包類型", "模式", "指標", *ALGS, "變化幅度(%)"], rows)

    _plot(sizes, comp, trip, out, "mid")
    params = {
        "command": " ".join(["python3 -m sim.pqc_compare", *sys.argv[1:]]),
        "git_commit": _git_commit(), "run_at": time.strftime("%Y-%m-%d %H:%M:%S"), "elapsed_s": round(elapsed, 1),
        "algorithms": list(ALGS), "iterations": args.iterations, "trials": args.trials, "envs": args.envs,
        "channel": "iid", "trip_costs": "calibrated per algorithm (trip_sim --calibrate)",
        "sizes": sizes,
        "notes": ["每個演算法在獨立暫存目錄重新佈建金鑰 (CA 根金鑰、CA 後量子憑證、車輛金鑰皆使用該演算法)",
                  "Falcon-512 為 NIST 安全等級 1，ML-DSA-44 為等級 2"],
    }
    with open(os.path.join(out, "params.json"), "w", encoding="utf-8") as f:
        json.dump(params, f, ensure_ascii=False, indent=2)
    print(f"完成 ({elapsed:.1f}s)，輸出至 {out}/", file=sys.stderr)


if __name__ == "__main__":
    main()
