"""
執行全部 ProVerif 情境並彙整結果。

用法 (於專案根目錄)：
  python3 -m security.proverif.run_proverif
  PROVERIF=/path/to/proverif python3 -m security.proverif.run_proverif

輸出：
  security/results/proverif_results.csv     每個情境 × 每個性質的驗證結果
  security/results/proverif_<情境>.txt      ProVerif 完整輸出 (含攻擊路徑)
"""
import csv, os, re, shutil, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCENARIOS = [
    ("classical",       "classical attacker, design at commit 86e284f (open CA enrollment, unsigned SSM)"),
    ("classical_fixed", "classical attacker, fixed design as implemented (F-1..F-6)"),
    ("quantum",         "quantum attacker (all ECC keys broken), design at commit 86e284f"),
    ("quantum_fixed",   "quantum attacker (all ECC keys broken), fixed design as implemented (F-1..F-6)"),
]

# 性質代碼：以查詢字串樣式判斷
PROPERTIES = [
    (r"^inj-event\(RSUGreen\(idA",   "green_injective",   "each SRM triggers at most one green (replay)"),
    (r"^event\(RSUGreen\(idA",       "green_auth",        "green for idA implies idA sent that SRM"),
    (r"^event\(RSUYellow\(idA",      "yellow_auth",       "flashing yellow for idA implies idA sent that SRM"),
    (r"^event\(RSUGreen\(i(_\d+)?,",        "green_authorized",  "green only for CA-enrolled emergency vehicles"),
    (r"^not event\(Blacklist\(idA",  "no_blacklist",      "attacker cannot get the honest vehicle blacklisted"),
    (r"^event\(OBUAcceptSSM",        "ssm_auth",          "SSM accepted by OBU was sent by the RSU"),
    (r"^not attacker\(pskA",         "secret_pq_key",     "vehicle ML-DSA private key stays secret"),
    (r"^not attacker\(pskCA",        "secret_ca_pq_key",  "CA ML-DSA private key stays secret"),
    (r"^not attacker\(skCA",         "secret_ca_ecc_key", "CA ECC private key stays secret"),
]

HEADERS = {"scenario": "情境", "scenario_desc": "情境說明", "property": "性質代碼",
           "property_desc": "性質說明", "result": "驗證結果", "query": "ProVerif 查詢"}


def find_proverif():
    for cand in (os.environ.get("PROVERIF"), shutil.which("proverif"),
                 os.path.expanduser("~/.local/src/proverif-src/proverif")):
        if cand and os.path.exists(cand):
            return cand
    sys.exit("找不到 proverif，請設定環境變數 PROVERIF 或將其加入 PATH")


def main():
    pv = find_proverif()
    out_dir = "security/results"
    os.makedirs(out_dir, exist_ok=True)
    rows = []
    for name, desc in SCENARIOS:
        proc = subprocess.run([pv, "-lib", os.path.join(HERE, "common"), os.path.join(HERE, f"{name}.pv")],
                              capture_output=True, text=True, timeout=600)
        log = proc.stdout + proc.stderr
        with open(os.path.join(out_dir, f"proverif_{name}.txt"), "w", encoding="utf-8") as f:
            f.write(log)
        results = re.findall(r"^RESULT (.+) is (true|false|cannot be proved)\.$", log, re.M)
        if not results:
            sys.exit(f"[{name}] 沒有任何 RESULT，請檢查 {out_dir}/proverif_{name}.txt")
        for query, verdict in results:
            code, pdesc = next(((c, d) for pat, c, d in PROPERTIES if re.match(pat, query)), ("other", ""))
            rows.append({"scenario": name, "scenario_desc": desc, "property": code, "property_desc": pdesc,
                         "result": verdict, "query": query})
            print(f"  {name:<16} {code:<18} {verdict}")

    with open(os.path.join(out_dir, "proverif_results.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(HEADERS.values())
        for r in rows:
            w.writerow(r[k] for k in HEADERS)


if __name__ == "__main__":
    main()
