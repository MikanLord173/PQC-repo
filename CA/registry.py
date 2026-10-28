"""
CA 車輛註冊名冊 (F-3)：

【安全修正】原本 CA 對任何 TCP 0x57 請求都發憑證，攻擊者可冒名註冊 AMB-217。
現在車輛必須事先在受控環境 (監理站 / 原廠) 登記，由 CA 決定其角色並發放一把 32 B 註冊金鑰；
註冊請求須附上以該金鑰計算的 HMAC，CA 驗證通過才發憑證，角色以名冊為準而非車輛自報。

用法 (模擬出廠配發；註冊金鑰同時寫入 OBU/keys/<ID>_enroll.key)：
  python3 -m CA.registry AMB-217 --role 14
  python3 -m CA.registry CAR-0042 --role 0
"""
import argparse, json, os, secrets

import pki

REGISTRY_PATH = "CA/registry.json"


def load_registry(path=REGISTRY_PATH) -> dict:
    """{obu_id: {"role": int, "enroll_key": hex}}；檔案不存在視為空名冊。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def register_vehicle(obu_id: str, role: int, path=REGISTRY_PATH) -> bytes:
    """登記車輛並產生新的註冊金鑰 (重複登記即輪替金鑰)。回傳註冊金鑰。"""
    registry = load_registry(path)
    enroll_key = secrets.token_bytes(32)
    registry[obu_id] = {"role": role, "enroll_key": enroll_key.hex()}
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(registry, f, indent=4)
    return enroll_key


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="在 CA 名冊登記車輛並配發註冊金鑰")
    ap.add_argument("obu_id")
    ap.add_argument("--role", type=int, default=pki.ROLE_AMBULANCE,
                    help="SAE J2735 BasicVehicleRole (0=一般車, 6=緊急, 12=警車, 13=消防, 14=救護車；預設 14)")
    args = ap.parse_args()

    key = register_vehicle(args.obu_id, args.role)
    os.makedirs("OBU/keys", exist_ok=True)
    with open(f"OBU/keys/{args.obu_id}_enroll.key", "wb") as f:
        f.write(key)
    print(f"已登記 {args.obu_id} (role={args.role})，註冊金鑰已配發至 OBU/keys/{args.obu_id}_enroll.key")
