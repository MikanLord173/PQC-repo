import socket, time, json, os, argparse
from OBU.encode_packet import gen_packet
from OBU.fragment import send_fragment
from OBU.gen_payload import format_temporary_id
import pki

# 配置參數
OBU_ID = "AMB-217"  # 車輛 ID，最多8字元
RSU_IP = "127.0.0.1" 
RSU_PORT = 5005
FREQUENCY = 5  # 發送頻率 (秒)

# 用計數器的方式取得ID
current_msg_id = 0
saved_intersections = {}

def get_next_id():
    global current_msg_id
    current_msg_id = (current_msg_id + 1) % 65536
    return current_msg_id

KNOWN_RSU_TTL = 60.0   # 已放行路口的白名單有效期 (秒)；預熱路口改用 SSM 夾帶的 prewarm_ttl_s

def check_intersection(intersection_id):
    """saved_intersections[路口] = 白名單到期時間 (Unix 秒)。
    【修正】原本記錄加入時間並固定 60 秒到期，與 RSU 預熱快取 TTL 不一致：RSU 先過期時 Short 封包會被回 status=6。"""
    inter_key = str(intersection_id)
    if inter_key in saved_intersections:
        if time.time() < saved_intersections[inter_key]:
            return True
        else:
            del saved_intersections[inter_key]
    return False

# 相容舊版名稱
check_RSU = check_intersection

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

SSM_MAX_AGE = 1.0   # 秒；拒絕過舊的 SSM (防止重放先前截獲的 status=6)
_ca_ecc_vk = None

def ssm_trusted(ssm):
    """
    【安全修正 F-6】只接受由 CA 核發憑證之 RSU 簽署、且夠新的 SSM。
    原本任何人都能偽造 status=6 迫使車輛退回 Full，或偽造 status=4 + prewarmed_rsus 讓車輛在下游誤用 Short。
    """
    global _ca_ecc_vk
    if _ca_ecc_vk is None:
        from ecdsa import VerifyingKey
        with open("OBU/keys/ca_ecc_pub.key", "rb") as f:
            _ca_ecc_vk = VerifyingKey.from_der(f.read())
    if abs(time.time() - ssm.get("full_timestamp", 0)) > SSM_MAX_AGE:
        return False
    return pki.verify_ssm(ssm, _ca_ecc_vk)

def send_heartbeat(obu_id, frequency, target_intersection=1, mode="dup"):
    """
    mode 實驗切換旗標：
      'none' → 策略 A：無冗餘基線（僅發資料分片，不發備用 F1）
      'dup'  → 策略 B：F1 主動復製（原有預設）
      'xor'  → 策略 C：XOR 單同位元修復分片（方向四研究模組）
    """
    print(f"--- OBU {obu_id} 啟動，目標路口 ID: {target_intersection}，傳輸通道: {RSU_IP}:{RSU_PORT}，發送頻率: {frequency}s，模式: {mode} ---")
    sock.settimeout(0.3)
    try:
        while True:
            is_known = check_intersection(target_intersection)
            packet   = gen_packet(obu_id, intersection_id=target_intersection, known_RSU=is_known)

            # ─── 實驗模式分洺 ──────────────────────────────────────────────────
            if mode == "xor":
                from fec import send_fragment_xor
                send_fragment_xor(sock, get_next_id(), packet, (RSU_IP, RSU_PORT))
            elif mode == "dup":
                send_fragment(sock, get_next_id(), packet, (RSU_IP, RSU_PORT), duplicate_f1=True)
            else:  # none
                send_fragment(sock, get_next_id(), packet, (RSU_IP, RSU_PORT), duplicate_f1=False)
            # ────────────────────────────────────────────────────────────

            # 監聽並解析 RSU 下行的 SAE J2735 SSM (msgID=30)
            try:
                ack_data, _ = sock.recvfrom(2048)
                ack_json = json.loads(ack_data.decode('utf-8'))
                if ack_json.get("msgID") == 30 and not ssm_trusted(ack_json):
                    print("[安全防護] 收到未通過 RSU 簽章驗證或已過期的 SSM，忽略\n")
                elif ack_json.get("msgID") == 30: # SSM (Signal Status Message)
                    for status_entry in ack_json.get("status", []):
                        ack_inter_id = status_entry.get("id", {}).get("id")
                        status_list = status_entry.get("sigStatus", [])
                        for item in status_list:
                            req_entity = item.get("requester", {}).get("id", {}).get("entityID")
                            st = item.get("status")
                            if req_entity in (obu_id, format_temporary_id(obu_id)):
                                if st == 4: # 4 = granted
                                    if not is_known:
                                        print(f"【收到路口 {ack_inter_id} 之 SSM 綠燈核准回條】首次建聯放行！切換為 Short 模式。\n")
                                    saved_intersections[str(ack_inter_id)] = time.time() + KNOWN_RSU_TTL

                                    # ─── 有線骨幹預熱授權清單批次更新 (免冷啟動) ───
                                    prewarmed = ack_json.get("prewarmed_rsus", [])
                                    ttls = ack_json.get("prewarm_ttl_s") or [KNOWN_RSU_TTL] * len(prewarmed)
                                    for next_rsu, ttl in zip(prewarmed, ttls):
                                        saved_intersections[str(next_rsu)] = time.time() + float(ttl)
                                        print(f"  [有線預熱授權] 下游路口 {next_rsu} 已同步金鑰，一併納入白名單！")
                                    break
                                elif st in (5, 6): # 5=rejected, 6=need_cert (Fallback)
                                    inter_key = str(ack_inter_id)
                                    if inter_key in saved_intersections:
                                        del saved_intersections[inter_key]
                                    print(f"[降級通知] 路口 {ack_inter_id} 要求補憑證 (status={st})，已從白名單移除，下週期降級回 Full 模式！\n")
                                    break
            except socket.timeout:
                if not is_known:
                    print(f"[提示] 未收到路口 {target_intersection} 的 SSM 核准回條 (可能空中掉包)，下一週期保持 Full 模式重試。\n")
                else:
                    # 【修降級條件】：逾時僅代表無線通道隨機掉包，不代表 RSU 快取丟失！
                    # 依據安全策略：OBU 僅在收到 status=6 (Need Cert) 時才移除白名單；逾時則維持 Short 模式繼續重試！
                    print(f"[提示] Short 模式未收到路口 {target_intersection} 回條 (無線通道隨機掉包)，維持 Short 模式重試。\n")

            time.sleep(frequency)
    except KeyboardInterrupt:
        print("\nOBU 已停止發送")
    finally:
        with open("OBU/json/saved_intersections.json", "w") as f:
            json.dump(saved_intersections, f, indent=4)
        sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OBU 緊急車輛廣播發送端")
    parser.add_argument("obu_id",       nargs="?",  default="AMB-217", help="車輛 ID (預設: AMB-217)")
    parser.add_argument("frequency",    nargs="?",  type=float, default=5.0, help="發送頻率 (秒，預設: 5.0)")
    parser.add_argument("--intersection", type=int, default=1,    help="目標路口編號 (預設: 1)")
    parser.add_argument("--mode",       choices=["none", "dup", "xor"], default="dup",
                        help="冗餘策略: none=無冗餘基線(A) | dup=F1復製(B,預設) | xor=XOR修復分片(C)")
    args = parser.parse_args()

    try:
        with open("OBU/json/saved_intersections.json", "r") as f:
            saved_intersections = json.load(f)
    except Exception:
        saved_intersections = {}

    send_heartbeat(args.obu_id, args.frequency, target_intersection=args.intersection, mode=args.mode)