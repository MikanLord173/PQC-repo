"""
離線佈建：在指定工作目錄一次完成 CA / RSU / OBU 金鑰與憑證 (不需啟動 CA.listen)

等同依序執行
  python3 -m CA.gen_keys → python3 -m RSU.setup → python3 -m CA.registry <ID> --role 14 → python3 -m OBU.setup <ID>
差別在於 OBU 註冊請求直接呼叫 CA.listen.handle_enrollment (同樣經過名冊 HMAC 驗證)，不經 TCP。
後量子演算法依環境變數 PQC_SIG_ALG (預設 ML-DSA-44)；用於在獨立目錄建立 Falcon-512 對照組，
不會覆蓋專案根目錄現有的 ML-DSA-44 金鑰。

用法 (於專案根目錄)：
  PQC_SIG_ALG=Falcon-512 python3 -m sim.provision --dir /tmp/pqc_falcon
之後在該目錄執行實驗 (程式碼仍從專案根目錄載入)：
  cd /tmp/pqc_falcon && PQC_SIG_ALG=Falcon-512 PYTHONPATH=<專案根目錄> python3 -m sim.trip_sim ...
"""
import argparse, contextlib, io, os, sys

import pki


def provision(workdir, obu_ids=("AMB-217",), role=pki.ROLE_AMBULANCE, quiet=True):
    """在 workdir 建立完整金鑰環境。回傳使用的後量子演算法名稱。"""
    os.makedirs(workdir, exist_ok=True)
    prev = os.getcwd()
    os.chdir(workdir)
    try:
        out = io.StringIO() if quiet else sys.stdout
        with contextlib.redirect_stdout(out):
            from CA.gen_keys import write_ca_root_keys
            from CA.registry import register_vehicle
            from CA.listen import handle_enrollment
            from RSU.setup import fetch_ca_keys, provision_rsu_keys
            from OBU.setup import setup

            write_ca_root_keys()
            # fetch_ca_keys 連不到 CA 時會改從本地 CA/keys 複製；直接指向不存在的埠避免等待逾時
            assert fetch_ca_keys(ca_ip="127.0.0.1", ca_port=1), "RSU 取得 CA 公鑰失敗"
            assert provision_rsu_keys(), "RSU SSM 金鑰配發失敗"

            def request(obu_id_bytes, R_U_bytes, obu_pqc_pub, enroll_key):
                resp = handle_enrollment(obu_id_bytes, R_U_bytes, obu_pqc_pub,
                                         pki.enroll_mac(enroll_key, obu_id_bytes, R_U_bytes, obu_pqc_pub))
                return resp if resp is not None else b''

            os.makedirs("OBU/keys", exist_ok=True)
            for obu_id in obu_ids:
                key = register_vehicle(obu_id, role)
                with open(f"OBU/keys/{obu_id}_enroll.key", "wb") as f:
                    f.write(key)
                assert setup(obu_id, request=request), f"{obu_id} 註冊失敗"
    finally:
        os.chdir(prev)
    return pki.pqc_alg()


def main():
    ap = argparse.ArgumentParser(description="在獨立目錄離線佈建 CA / RSU / OBU 金鑰 (演算法依 PQC_SIG_ALG)")
    ap.add_argument("--dir", required=True, help="工作目錄 (會在其中建立 CA/、RSU/、OBU/)")
    ap.add_argument("--obu", nargs="+", default=["AMB-217"], help="要註冊的車輛 ID")
    args = ap.parse_args()
    alg = provision(args.dir, args.obu, quiet=False)
    print(f"已在 {args.dir} 完成 {alg} 佈建")


if __name__ == "__main__":
    main()
