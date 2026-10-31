import socket, time, os
# 【修正】process_fragment 解析 F1 時間戳需要模組層級的 json；
# 原本只有函式內局部 import，導致 json.loads 丟 NameError 被 except 吃掉，
# f1_ts 永遠等於 now → 「舊/重複 F1 去重」永遠不成立，重放的 F1 反而會取代合法會話。
import json
import RSU.parse as parse
import pki

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    if os.path.exists(".env"):
        with open(".env", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

# 核心配置參數
RSU_ID   = int(os.getenv("RSU_ID", 1))
RSU_IP   = os.getenv("RSU_LISTEN_IP", "0.0.0.0") 
RSU_PORT = int(os.getenv("RSU_PORT", 5005))
BUFFER_SIZE = 4096
PRUNING_TIMEOUT = 0.08 # 80 毫秒（配合 150ms 端到端延遲）
SOCKET_TIMEOUT = 0.01   # 10 毫秒輪詢週期，Non-blocking
PRUNE_INTERVAL = 0.005  # 逾時清理最短間隔 (秒)；原本每收一包就掃描整個暫存池，洪水攻擊下 CPU 大量耗在清理

# ─── 下游拓樸鄰居表（Topology Lookup Table） ──────────────────────────────────
# 定義幹道路口有向圖：{當前路口ID: {方向/進口道: [下游RSU清單], "default": [下游RSU清單]}}
DOWNSTREAM_TOPOLOGY = {
    1: {"eastbound": [2, 3], "northbound": [4], "default": [2, 3]},
    2: {"eastbound": [3], "default": [3]},
    3: {"eastbound": [4], "default": [4]},
    4: {"default": []}
}

# 路口間行車距離 (公尺)，用於估計車輛抵達下游路口的時間與預熱快取有效期 (TTL)
DOWNSTREAM_DISTANCE_M = {(1, 2): 300.0, (1, 3): 600.0, (2, 3): 300.0, (3, 4): 300.0}
DEFAULT_SEGMENT_M     = 300.0   # 未列於上表時採用
PREWARM_GRACE_S       = 30.0    # TTL 額外寬限 (秒)
PREWARM_SLOWDOWN      = 2.0     # 允許車輛平均速度降為 SRM 車速的 1/2 (壅塞、減速通過路口)
# 【修正】原本 ETA 一律以 300 公尺估算 (TTL = 300m / 車速 + 30s)，與實際路口間距無關：
# 間距較大 (例如 900 公尺、60 km/h 需 54 秒) 時，車輛抵達前快取就已過期 → Short 封包被回 status=6 再補 Full，
# 而 OBU 端白名單固定 60 秒，兩邊的有效期也不一致。現改為依實際距離估算，並在 SSM 夾帶 TTL 讓 OBU 同步。
PREWARM_LEGACY_TTL    = False   # True = 舊公式 (僅供實驗對照)
LAST_PREWARM_TTL      = {}      # 最近一次預熱：{下游路口: TTL 秒}

def prewarm_ttl(current_id: int, target_id: int, speed_mps: float) -> float:
    """預熱快取有效期 (秒)。"""
    if PREWARM_LEGACY_TTL:
        eta = 300.0 / speed_mps if speed_mps > 2.0 else 18.0
        return eta + 30.0
    dist = DOWNSTREAM_DISTANCE_M.get((current_id, target_id), DEFAULT_SEGMENT_M)
    speed = speed_mps if speed_mps > 2.0 else 300.0 / 18.0     # 車速未知時以 60 km/h 估算
    return dist / speed * PREWARM_SLOWDOWN + PREWARM_GRACE_S

def get_downstream_rsus(current_id: int, srm_data: dict = None) -> list:
    """根據拓樸圖與車輛 SRM 行駛資訊查出下游路口清單"""
    topo = DOWNSTREAM_TOPOLOGY.get(current_id, {})
    if isinstance(topo, list):
        return list(topo)
    return list(topo.get("default", []))

def trigger_inter_rsu_prewarm(current_rsu_id: int, obu_id_raw: bytes, P_U_bytes: bytes,
                              vk_ecc, obu_pqc_pub: bytes, srm_data: dict = None,
                              rsu_cluster: dict = None, role: int = None) -> list:
    """
    路側有線骨幹 (Backhaul) 主動預同步：
    當 RSU 完成雙簽驗證後，透過有線骨幹網路將 (Q_U, PK_PQC, ETA) 主動注入下游路口。
    下游路口免算點乘重構，實現零冷啟動！
    """
    downstream_ids = get_downstream_rsus(current_rsu_id, srm_data)
    if not downstream_ids:
        return []

    # 依 SRM 車速與路口間距估計抵達時間，計算各下游路口的快取有效期 (見 prewarm_ttl)
    speed_mps = 0.0
    if srm_data:
        pos = srm_data.get("requestor", {}).get("position", {})
        speed_mps = pos.get("speed", {}).get("speed", 0) * 0.02

    prewarmed_list = []
    LAST_PREWARM_TTL.clear()
    for target_id in downstream_ids:
        ttl = prewarm_ttl(current_rsu_id, target_id, speed_mps)
        expire_at = time.time() + ttl
        LAST_PREWARM_TTL[target_id] = ttl
        if rsu_cluster and target_id in rsu_cluster:
            target_rsu = rsu_cluster[target_id]
            target_rsu.inject_prewarm(obu_id_raw, P_U_bytes, vk_ecc, obu_pqc_pub, expire_at, role=role)
        else:
            parse.inject_prewarm_cache(target_id, obu_id_raw, P_U_bytes, vk_ecc, obu_pqc_pub, expire_at, role=role)
        prewarmed_list.append(target_id)
        print(f"  [有線骨幹預同步] 已將已驗證金鑰 (Q_U, PK_PQC) 推送至下游路口 {target_id} (TTL: {ttl:.0f}s)")

    return prewarmed_list

# ─── 安全防護配置 ───────────────────────────────────────────────────────────
BLACKLIST_DURATION       = 30.0     # 密碼學硬封鎖持續時間（秒，具 TTL 自動解除）
IP_WINDOW                = 1.0      # 來源 IP 滑動視窗長度（秒）
IP_MAX_PACKETS           = 50       # 單一來源 IP 每秒最高封包數（超過即丟棄，軟限流）
IP_MAX_TRACKED           = 1000     # IP 限流字典上限（LRU 防記憶體耗盡）

OBU_F1_WINDOW            = 1.0      # 已認證 OBU F1 滑動視窗（秒）
OBU_F1_MAX_RATE          = 10       # 單一合法 OBU 每秒最高允許 10 次 F1（正常 1~2Hz，超過軟限流不封鎖）
OBU_F1_MAX_TRACKED       = 500      # OBU 限流字典上限

XOR_MAX_PARITY_CANDIDATES = 3       # 每個 XOR 會話最多保留的 FP 候選數 (FP 無雜湊承諾，需容納偽造 FP)

MAX_SESSIONS             = 100      # 重組暫存池上限 (多車並發會話數；每會話約 7KB，全滿約 0.7MB RAM)
# 【修正】暫存池滿時優先淘汰「尚未通過 F1 認證」的會話。原本一律淘汰最早建立的會話，
# 攻擊者以大量偽造來源灌入只有 F2 的假會話，就能把已閃黃燈、正在收後續分片的救護車會話擠出暫存池。
EVICT_UNAUTHENTICATED_FIRST = True
PRE_F1_SLOT_CANDIDATES   = 3        # F1 抵達前每個序號最多暫存的候選分片數 (尚無雜湊承諾可篩選)
# 【修正】來源 IP 限流只套用在 F1 (唯一需要 ECC 驗簽的分片)。無線網路可偽造來源位址，攻擊者冒用救護車 IP
# 狂送垃圾後續分片，原本會耗盡救護車自己的限流額度，使其合法分片被丟棄；後續分片只做雜湊比對，
# 記憶體由 MAX_SESSIONS 與 PRE_F1_SLOT_CANDIDATES 限制，不需靠 IP 限流保護。
RATE_LIMIT_F1_ONLY = True

# ──────────────────────────────────────────────────────────────────────────

# 重組緩衝區，key= (msg_id, addr)
# value 為 session dict: {"state": ..., "start_time": ..., "total_frags": ..., "fragments": [...], "created_at": ..., "obu_id": ..., "f1_timestamp": ...}
reassemble_buffer = {}

# 最近已完成重組的 (msg_id, addr)，避免尾巴重複分片再次觸發新 session
recent_completed = {}

# 【安全修正 F-4】最近已放行的 SRM：recent_granted[(obu_id, full_timestamp)] = 放行時間。
# recent_completed 以 (msg_id, 來源位址) 為鍵，攻擊者在 150ms 時效內換個來源位址重放已完成的請求，
# 會被當成新會話再放行一次。改以「車輛 ID + SRM 時間戳」辨識同一則請求。
recent_granted = {}
GRANT_DEDUP_WINDOW = 2.0   # 秒；需大於 150ms 時效視窗

# ─── 活躍會話索引 & 密碼學硬黑名單 ──────────────────────────────────────────
# id_active_session[obu_id] = session_key  →  快速查詢該 ID 當前佔用的 session
id_active_session = {}

# id_session_meta[obu_id] = {"msg_id": ..., "f1_timestamp": ...}  →  防重放與會話搶佔判定
id_session_meta = {}

# 來源 IP 軟限流：ip_rate_log[ip_str] = [timestamp, ...] (OrderedDict 實作 LRU)
from collections import OrderedDict
ip_rate_log = OrderedDict()

# 已認證 OBU F1 軟限流：obu_f1_rate_log[obu_id] = [timestamp, ...] (OrderedDict 實作 LRU)
obu_f1_rate_log = OrderedDict()

# 密碼學硬黑名單 (僅記錄有確鑿密碼學偽造證據的 obu_id): blacklist[obu_id] = ban_until
blacklist = {}
# ──────────────────────────────────────────────────────────────────────────

def trigger_hard_blacklist(obu_id: str, reason: str, now: float = None):
    """
    【密碼學確鑿證據硬封鎖 (具 TTL)】
    全系統「唯一」合法封鎖 obu_id 的條件：
      - F1 已通過 ECC 簽章認證其合法身分
      - 所有後續分片均符合 F1 承諾之 SHA-256 雜湊（攻擊者無法中間篡改）
      - 重組後 ML-DSA-44 / ECQV 驗簽失敗！
      證明只有真正持有私鑰的實體蓄意偽造後量子簽章。
    """
    if now is None:
        now = time.time()
    ban_until = now + BLACKLIST_DURATION
    blacklist[obu_id] = ban_until
    print(f"\n[安全防護 ⚠ 密碼學確鑿證據硬封鎖] 車輛 ID={obu_id} 原因: {reason}")
    print(f"  → 確定持有金鑰主體惡意偽造，硬封鎖 {BLACKLIST_DURATION:.0f}s，直至 {time.strftime('%H:%M:%S', time.localtime(ban_until))}\n")

def check_ip_rate_limit(ip_str: str, now: float) -> bool:
    """
    來源 IP 級別軟限流 (以 IP 為鍵，避免更換 port 繞過)。
    使用 OrderedDict 維護上限 1,000 筆，防止攻擊者隨機造 IP 撐爆 RSU 記憶體。
    回傳 True 表示允許通行，False 表示超額丟棄。
    """
    if ip_str in ip_rate_log:
        ip_rate_log.move_to_end(ip_str)
        log = ip_rate_log[ip_str]
    else:
        if len(ip_rate_log) >= IP_MAX_TRACKED:
            ip_rate_log.popitem(last=False)  # 淘汰最舊的 IP
        log = []
        ip_rate_log[ip_str] = log

    log[:] = [t for t in log if now - t < IP_WINDOW]
    if len(log) >= IP_MAX_PACKETS:
        return False  # 超過每秒 50 包，軟限流靜默丟棄
    log.append(now)
    return True

def check_obu_f1_rate_limit(obu_id: str, now: float) -> bool:
    """
    已認證 OBU F1 軟限流：防止持有憑證的惡意節點狂發有效 F1 消耗 CPU 與記憶體。
    超過 10 Hz 即靜默忽略，不加黑名單、不封鎖。
    """
    if obu_id in obu_f1_rate_log:
        obu_f1_rate_log.move_to_end(obu_id)
        log = obu_f1_rate_log[obu_id]
    else:
        if len(obu_f1_rate_log) >= OBU_F1_MAX_TRACKED:
            obu_f1_rate_log.popitem(last=False)
        log = []
        obu_f1_rate_log[obu_id] = log

    log[:] = [t for t in log if now - t < OBU_F1_WINDOW]
    if len(log) >= OBU_F1_MAX_RATE:
        return False
    log.append(now)
    return True

# 定時檢查
def prune_expired_sessions():
    now = time.time()
    # 清理超過 2 秒的已完成紀錄
    for key, done_time in list(recent_completed.items()):
        if now - done_time > 2.0:
            del recent_completed[key]

    for key, granted_at in list(recent_granted.items()):
        if now - granted_at > GRANT_DEDUP_WINDOW:
            del recent_granted[key]

    # 清理已過期的黑名單條目 (TTL 自動過期解除)
    for identifier in list(blacklist.keys()):
        if now >= blacklist[identifier]:
            del blacklist[identifier]
            print(f"[安全防護] 車輛 {identifier} 密碼學黑名單 TTL 已到期，自動解除封鎖")

    pruned_keys = []
    for key, session in list(reassemble_buffer.items()):
        # 若 F1 已抵達，以 F1 抵達時間倒數 80ms
        if session["start_time"] is not None:
            elapsed = now - session["start_time"]
            if elapsed > PRUNING_TIMEOUT:
                pruned_keys.append((key, elapsed))
        # 沒收到F1，超過 1 秒同樣清空
        elif now - session["created_at"] > 1.0:
            pruned_keys.append((key, 1.0))

    for key, elapsed in pruned_keys:
        msg_id, addr = key
        session = reassemble_buffer[key]
        obu_id = session.get("obu_id")  # 若 F1 通過 ECC 驗證則存在
        print(f"\n[超時清理] 訊息 ID={msg_id} [來自 {addr}] 逾時 ({elapsed*1000:.1f}ms > {PRUNING_TIMEOUT*1000:.0f}ms) 碎片不齊")
        print(f"清空快取，號誌維持正常週期")
        del reassemble_buffer[key]

        # 清理 Per-ID 活躍 session 索引
        if obu_id:
            if id_active_session.get(obu_id) == key:
                del id_active_session[obu_id]
            if obu_id in id_session_meta and id_session_meta[obu_id].get("msg_id") == msg_id:
                del id_session_meta[obu_id]

        # 【關鍵安全修復：黑名單策略】：
        # 1. 通過 F1 ECC 驗證後才逾時的會話屬於「已認證的掉包」，絕不記懲罰封鎖！
        #    防範重大漏洞：若逾時就懲罰，攻擊者重放救護車的 F1 (150ms 內有效) 卻不發後續分片，
        #    即可蓄意誘發 RSU 逾時而使合法救護車被封鎖 (Replay-to-Block DoS 漏洞)。
        # 2. 未通過 F1 驗證即逾時的匿名碎片堆積，直接釋放記憶體即可，由 IP 限流防範頻寬攻擊。
        if obu_id:
            print(f"  [已認證掉包] 車輛 ID={obu_id} 之 F1 已通過 ECC 認證，後續分片未達屬於自然通道衰落，不計懲罰封鎖。\n")
        else:
            print(f"  [未認證超時] 匿名來源 {addr} 超時（F1 未通過驗證），清除碎片暫存。\n")

# ─── SSM 簽章 (F-6) ───────────────────────────────────────────────────────────
# 【安全修正 F-6】原本下行 SSM 是明文 JSON，任何人都能偽造 status=6 迫使車輛退回 Full (多耗頻寬)，
# 或偽造 status=4 + prewarmed_rsus 讓車輛在下游誤用 Short。現在每個 RSU 持有 CA 簽發的 ECDSA 金鑰，
# SSM 夾帶 RSU 憑證與簽章，OBU 驗證後才更新白名單。金鑰由 python3 -m RSU.setup 配發。
_rsu_signers = {}

def _rsu_signer(rsu_id):
    if rsu_id not in _rsu_signers:
        from ecdsa import SigningKey
        with open(f"RSU/keys/rsu_{rsu_id}_ecc_priv.key", "rb") as f:
            sk = SigningKey.from_der(f.read())
        with open(f"RSU/keys/rsu_{rsu_id}_cert.json", "r", encoding="utf-8") as f:
            cert = json.load(f)
        _rsu_signers[rsu_id] = (sk, cert)
    return _rsu_signers[rsu_id]

def send_signed_ssm(sock, ssm_payload, addr, rsu_id):
    sk, cert = _rsu_signer(rsu_id)
    ssm_bytes = json.dumps(pki.sign_ssm(ssm_payload, sk, cert), separators=(',', ':')).encode('utf-8')
    sock.sendto(ssm_bytes, addr)
    return ssm_bytes

# ─── 共用：重組完成後的密碼驗證與 SSM 回條（DUP 與 XOR 兩個路徑共用）─────────
def _finalize_session(session_key, session, packet, addr, sock, rsu_id=None):
    """封包重組完成後，清理緩衝區並執行密碼驗證→放行流程。"""
    current_rsu = rsu_id if rsu_id is not None else RSU_ID
    del reassemble_buffer[session_key]
    recent_completed[session_key] = time.time()
    # 清除 Per-ID 活躍 session 索引
    obu_id_done = session.get("obu_id")
    if obu_id_done:
        if id_active_session.get(obu_id_done) == session_key:
            del id_active_session[obu_id_done]
        if obu_id_done in id_session_meta:
            del id_session_meta[obu_id_done]

    payload = parse.parse_packet(packet, rsu_id=current_rsu)
    if payload:
        total_latency = time.time() - payload['full_timestamp']
        if total_latency > 0.15:
            print(f"\n[逾期] 封包總延遲 ({total_latency*1000:.1f}ms > 150ms)，疑似重放攻擊！")
            print(f"拒絕放行，號誌維持正常週期\n")
            return

        # 【安全修正 F-4】同一則 SRM (車輛 ID + 時間戳) 只放行一次
        grant_key = (parse.LAST_VERIFIED_AUTH.get("obu_id_str"), payload['full_timestamp'])
        if grant_key in recent_granted:
            print(f"\n[安全防護 重放] 車輛 {grant_key[0]} 的 SRM (ts={grant_key[1]:.3f}) 已放行過，拒絕重複放行\n")
            return
        recent_granted[grant_key] = time.time()

        print(f"\n[來自 {addr}] 驗證成功，切換緊急綠燈")
        print(f"[Pre-warming] 向鄰近號誌發送預熱訊號")
        print(f"端到端總耗時：{total_latency:.4f} 秒")
        print(f"\n完整訊息：")
        if payload.get("msgID") == 29:
            req_pkg    = payload.get("requests", [{}])[0].get("request", {})
            requestor  = payload.get("requestor", {})
            req_id     = requestor.get("id", {}).get("entityID")
            role       = requestor.get("type", {}).get("role")
            pos        = requestor.get("position", {})
            inter_id   = req_pkg.get('id', {}).get('id', current_rsu)
            approach_id= req_pkg.get('inBoundLane', {}).get('approach', 1)
            req_num    = req_pkg.get('requestID', 1)

            print(f"  [SAE J2735 SRM 優先號誌請求]")
            print(f"  車輛識別: {req_id} (角色代碼: {role}=Ambulance, 優先等級: {requestor.get('type', {}).get('request')})")
            print(f"  目標路口: {inter_id}, 請求進口道 Approach: {approach_id}")
            print(f"  座標: (Lat {pos.get('position', {}).get('lat')/1e7:.6f}, Lon {pos.get('position', {}).get('long')/1e7:.6f}), 速度: {pos.get('speed', {}).get('speed', 0)*0.02*3.6:.1f} km/h")

            # ─── 觸發有線骨幹主動預同步 (Backhaul Proactive Sync) ───
            last_auth = parse.LAST_VERIFIED_AUTH
            prewarmed_rsus = []
            if last_auth and last_auth.get("vk") and last_auth.get("pqc_pub"):
                prewarmed_rsus = trigger_inter_rsu_prewarm(
                    current_rsu_id=inter_id,
                    obu_id_raw=last_auth["obu_id_raw"],
                    P_U_bytes=last_auth["P_U_bytes"],
                    vk_ecc=last_auth["vk"],
                    obu_pqc_pub=last_auth["pqc_pub"],
                    srm_data=payload,
                    role=last_auth["role"]
                )

            if sock is not None:
                from RSU.gen_payload import generate_ssm_payload
                ssm_payload = generate_ssm_payload(
                    obu_id=req_id,
                    intersection_id=inter_id,
                    approach_id=approach_id,
                    request_id=req_num,
                    status=4,
                    sequence_number=payload.get("sequenceNumber", 1),
                    prewarmed_rsus=prewarmed_rsus,
                    prewarm_ttl_s=[round(LAST_PREWARM_TTL.get(r, 0.0), 1) for r in prewarmed_rsus] or None
                )
                ssm_bytes = send_signed_ssm(sock, ssm_payload, addr, current_rsu)
                print(f"  -> 已向車輛 {req_id} 回傳已簽章 SAE J2735 SSM 放行回條 (ACK, {len(ssm_bytes)} bytes)")
                if prewarmed_rsus:
                    print(f"  -> SSM 夾帶預熱授權下游路口清單: {prewarmed_rsus}")
        else:
            for key, value in payload.items():
                if key == 'coreData':
                    print(f"{key}: ", end="{\n")
                    for sub_key, sub_value in value.items():
                        print(f"  {sub_key}: {sub_value}")
                    print("}")
                else:
                    print(f"{key}: {value}")
        print()
    else:
        print(f"\n驗證失敗，拒絕通行")
        print(f"號誌維持正常週期\n")
        # ─── 悲觀降級：若為 Short 模式 Cache Miss 或 Short 驗簽失敗，回傳 status=6 (Need Cert / Fallback) ───
        if parse.LAST_PARSE_STATUS in ("NEED_CERT", "SHORT_SIG_FAIL") and sock is not None:
            from RSU.gen_payload import generate_ssm_payload
            current_obu = session.get("obu_id", "AMB-217")
            # 若為 Short 模式驗簽失敗，視為快取不同步/損毀，清空該車公鑰快取
            if parse.LAST_PARSE_STATUS == "SHORT_SIG_FAIL":
                # 【修正】原呼叫的 parse.PURGE_OBU_CACHE 不存在 (AttributeError)，導致 status=6 送不出去，
                # 而 OBU 逾時不再降級 → 車輛會卡死在 Short 模式。改呼叫 parse.purge_obu_cache 並指定本路口。
                parse.purge_obu_cache(current_obu, rsu_id=current_rsu)
                print(f"  -> [Short 模式簽章比對未過] 視為快取失效/金鑰不同步，已清除快取，不予封鎖。")
            
            nack_payload = generate_ssm_payload(
                obu_id=current_obu,
                intersection_id=current_rsu,
                status=6
            )
            send_signed_ssm(sock, nack_payload, addr, current_rsu)
            print(f"  -> 已向車輛發送 Fast-NACK (status=6，要求降級退回 Full 模式重試)\n")
        elif parse.LAST_PARSE_STATUS == "FULL_SIG_FAIL":
            # 密碼學證據：ECC 簽章已承諾此 ML-DSA 簽章 (F-1)，公鑰經 ECQV 與 CA 後量子憑證綁定，但 ML-DSA 驗簽失敗。
            # 【安全修正 F-1】原本 ECC 不涵蓋 PQC 簽章，中間人竄改簽章即可觸發此封鎖 (T5)；
            # 現在中間人竄改會落在 PQC_SIG_HASH_MISMATCH (只丟棄不封鎖)。
            # 殘餘風險：量子攻擊者可偽造 ECC 簽章，仍能誘發此封鎖 (見 THREAT_MODEL.md Q1)。
            violator = session.get("obu_id") or str(addr)
            trigger_hard_blacklist(violator, "Full 模式下 ML-DSA-44 重組簽章驗證失敗 (強證據：偽造後量子簽章)")
        else:
            print(f"  -> 未知驗證失敗狀態 ({parse.LAST_PARSE_STATUS})，丟棄處理且不予封鎖。")


# ─── XOR 模式：修復嘗試 ────────────────────────────────────────────────────────
def _try_xor_recovery(session_key, session, addr, sock, rsu_id=None):
    """
    嘗試 XOR 單片修復。在每次 XOR session 新增分片 (F1, F2..FN, 或 FP) 後呼叫。
    前提：F1 必須已通過 ECC 驗證 (session["fragments"][0] is not None) 觸發閃黃燈。
    - 所有資料分片齊全 (F1..FN) → 直接重組（不需 FP）
    - F2..FN 缺恰一片 + 已收 FP → XOR 還原缺失片
    - 其他情況 → 繼續等待
    重組成功後，走標準密碼驗證流程 (_finalize_session)。
    """
    current_rsu = rsu_id if rsu_id is not None else RSU_ID
    total_frags = session["total_frags"]
    fragments   = session["fragments"]
    parity_list = session["xor_parity_candidates"]
    f1_raw      = fragments[0]

    # F1 尚未通過 ECC 驗證前，不進行重組
    if f1_raw is None:
        return

    n_heavy = total_frags - 1
    received_heavy = {
        i: fragments[i + 1]
        for i in range(n_heavy)
        if fragments[i + 1] is not None
    }
    n_recv_heavy = len(received_heavy)

    # Case A：所有重量資料分片全齊 → 直接拼接
    if n_recv_heavy == n_heavy:
        elapsed = (time.time() - session["start_time"]) * 1000 if session["start_time"] else 0
        print(f"[XOR] 來自 {addr} 資料分片全齊 (F1..F{total_frags})，直接重組 ({elapsed:.1f}ms)")
        heavy_raw = b''.join(received_heavy[i] for i in range(n_heavy))
        packet = f1_raw + heavy_raw
        _finalize_session(session_key, session, packet, addr, sock, rsu_id=current_rsu)
        return

    # Case B：F2..FN 缺一片 + 已收 FP → XOR 還原
    if n_recv_heavy == n_heavy - 1 and parity_list:
        from fec import recover_xor_heavy
        import hashlib
        missing_idx = next(i for i in range(n_heavy) if i not in received_heavy)
        missing_seq = missing_idx + 2
        exp_hashes = session.get("expected_hashes") or {}
        exp_h = exp_hashes.get(missing_seq)

        # 【修正】FP 不在 F1 雜湊承諾範圍內，任何人都能偽造。原本遇到污染的 FP 就刪除整個會話，
        # 攻擊者只要搶先送一個假 FP 就能讓救護車的合法會話作廢 (Parity-Poisoning DoS)。
        # 改為：逐一嘗試所有 FP 候選，雜湊不符者只淘汰該候選、保留會話，
        # 繼續等待真正的 FP 或缺失分片本身 (Case A)。
        for parity in list(parity_list):
            packet = recover_xor_heavy(received_heavy, parity, n_heavy, f1_raw)
            if packet is None:
                print(f"[XOR] FP 候選修復計算失敗（長度不符），淘汰此候選")
                parity_list.remove(parity)
                continue

            # ───【關鍵防嫁禍：驗證還原分片雜湊】───
            # 還原出的分片必須吻合 F1 承諾的 H(Fi)。若不吻合代表 FP 遭攻擊者偽造污染！
            if exp_h is not None:
                # packet = f1_raw + heavy_raw
                # 計算 offset: f1_raw + 前面 missing_idx 個分片長度
                offset = len(f1_raw)
                for i in range(missing_idx):
                    offset += len(received_heavy[i])
                # missing 分片長度 = total - 其他分片
                missing_frag_len = len(packet) - offset - sum(len(received_heavy[j]) for j in range(missing_idx + 1, n_heavy))
                recovered_chunk = packet[offset : offset + missing_frag_len]
                if hashlib.sha256(recovered_chunk).digest() != exp_h:
                    print(f"[XOR 污染攔截] 還原之 F{missing_seq} 雜湊與 F1 承諾不符！淘汰此偽造 FP，會話保留繼續等待 (不懲罰車輛)")
                    parity_list.remove(parity)
                    continue

            elapsed = (time.time() - session["start_time"]) * 1000 if session["start_time"] else 0
            print(f"[XOR 修復成功] 來自 {addr}，F{missing_seq}/{total_frags} 已還原且雜湊承諾吻合 ({elapsed:.1f}ms)，進行密碼驗證")
            _finalize_session(session_key, session, packet, addr, sock, rsu_id=current_rsu)
            return


def _evict_one_session():
    """暫存池已滿時淘汰一個會話 (見 EVICT_UNAUTHENTICATED_FIRST)。"""
    if EVICT_UNAUTHENTICATED_FIRST:
        # dict 依插入順序 = 建立先後；由舊到新找第一個未認證會話，通常第一筆即是 (O(1))
        victim = next((k for k, s in reassemble_buffer.items() if s.get("obu_id") is None),
                      next(iter(reassemble_buffer)))
    else:
        victim = min(reassemble_buffer, key=lambda k: reassemble_buffer[k]["created_at"])
    obu_id = reassemble_buffer[victim].get("obu_id")
    del reassemble_buffer[victim]
    if obu_id and id_active_session.get(obu_id) == victim:
        del id_active_session[obu_id]
        id_session_meta.pop(obu_id, None)


def _stash_pre_f1(session, seq_num, chunk_bytes):
    """
    F1 抵達前的後續分片：尚無雜湊承諾可驗證，每個序號保留最多 PRE_F1_SLOT_CANDIDATES 個不同候選 (先進先出)，
    F1 抵達後再依承諾挑出正確者。
    【修正】原本同一序號只保留最後到達的一片，攻擊者在合法分片之後補送一片假分片即可覆蓋，
    F1 抵達時雜湊不符被清除 → 合法分片已遺失，整則訊息作廢。
    """
    cands = session["pre_f1"].setdefault(seq_num, [])
    if chunk_bytes not in cands:
        cands.append(chunk_bytes)
        if len(cands) > PRE_F1_SLOT_CANDIDATES:
            # 保留最先到達的一片與最新的幾片：攻擊者在合法分片之後狂送假分片擠不掉最先到的合法分片，
            # 搶先送假分片時合法分片則留在「最新」區段
            cands.pop(1 if PRE_F1_SLOT_CANDIDATES > 1 else 0)
    if seq_num <= len(session["fragments"]):
        session["fragments"][seq_num - 1] = chunk_bytes



# 處理收到的分片
def process_fragment(data, addr, sock=None, rsu_id=None):
    current_rsu = rsu_id if rsu_id is not None else RSU_ID
    now = time.time()

    header_bytes = data[:4]
    chunk_bytes  = data[4:]
    # parse_header 現在回傳 4-tuple（is_xor 旗標由 total_frags byte 高位元決定）
    seq_num, total_frags, msg_id, is_xor = parse.parse_header(header_bytes)
    if seq_num is None:
        print(f"[來自 {addr}] 收到無效的 header")
        return
    if total_frags == 0:
        return  # 非法分片數

    session_key = (msg_id, addr)

    # 1. 來源 IP 軟限流 (以 IP 為鍵，上限 1000 筆 LRU，防止換 port 攻擊)；見 RATE_LIMIT_F1_ONLY
    ip_str = addr[0]
    if seq_num == 1 or not RATE_LIMIT_F1_ONLY:
        if not check_ip_rate_limit(ip_str, now):
            return  # 單一來源 IP 超過限流閾值，靜默丟棄

    # 若該訊息剛重組完成，忽略後續抵達的重複分片 (如尾巴備用 F1)
    if session_key in recent_completed:
        return

    # 多車暫存池上限保護 (上限 MAX_SESSIONS 台並發車輛)
    if session_key not in reassemble_buffer:
        if len(reassemble_buffer) >= MAX_SESSIONS:
            _evict_one_session()

        reassemble_buffer[session_key] = {
            "state"            : "WAITING_F1",
            "mode"             : "xor" if is_xor else None,  # 從第一片就確認模式
            "start_time"       : None,
            "total_frags"      : total_frags,
            "fragments"        : [None] * total_frags,
            "expected_hashes"  : None,
            "xor_parity_candidates": [],  # FP 候選清單 (最多 XOR_MAX_PARITY_CANDIDATES 個)
            "created_at"       : now,
            "obu_id"           : None,   # DUP/XOR 模式 F1 驗證後填入
            "f1_timestamp"     : 0.0,
            "pre_f1"           : {},     # F1 抵達前的候選分片 {seq: [chunk, ...]}
        }
    session = reassemble_buffer[session_key]
    # 若後續分片帶有 XOR 旗標，補充標記（應對 parity 先到的情況）
    if is_xor:
        session["mode"] = "xor"

    # ── seq_num == 0：XOR 修復分片 FP ──
    if seq_num == 0:
        # 【修正】原本「先到先得」只收第一個 FP，攻擊者搶先送假 FP 就會擠掉真的 FP。
        # 改為保留多個不重複的候選 (設上限防止灌 FP 耗 CPU)，由 _try_xor_recovery 以 F1 雜湊承諾篩選。
        candidates = session["xor_parity_candidates"]
        if chunk_bytes not in candidates and len(candidates) < XOR_MAX_PARITY_CANDIDATES:
            candidates.append(chunk_bytes)
            if session["start_time"] is None:
                session["start_time"] = time.time()
                session["state"] = "REASSEMBLING"
            print(f"[XOR] 來自 {addr} 收到修復分片 FP ({len(chunk_bytes)}B)")
            _try_xor_recovery(session_key, session, addr, sock, rsu_id=current_rsu)
        return

    # ── 1. 收到 F1 碎片 (首分片) ──
    if seq_num == 1:
        if session["fragments"][0] is None:
            f1_valid, obu_id_str, payload_bytes, exp_hashes, raw_f1 = parse.verify_f1_ecc(chunk_bytes, rsu_id=current_rsu)
            if f1_valid:
                # 提取 F1 時間戳 (用於防重放與取代舊會話)
                f1_ts = 0.0
                try:
                    f1_ts = json.loads(payload_bytes.decode('utf-8')).get("full_timestamp", now)
                except Exception:
                    f1_ts = now

                # 【安全修正 F-4】已放行過的同一則 SRM 不再開新會話 (連閃黃燈都不觸發)
                if (obu_id_str, f1_ts) in recent_granted:
                    print(f"[安全防護 重放] 車輛 {obu_id_str} 的 SRM (ts={f1_ts:.3f}) 已放行過，忽略重放的 F1")
                    del reassemble_buffer[session_key]
                    return

                # ─── 密碼學硬黑名單檢查 (車輛 ID 具 TTL，只有重組後 ML-DSA 失敗會被記) ───
                if obu_id_str in blacklist:
                    ban_until = blacklist[obu_id_str]
                    if now < ban_until:
                        remaining = ban_until - now
                        print(f"[安全防護 拒絕] 車輛 {obu_id_str} 處於密碼學確鑿證據硬封鎖中，剩餘 {remaining:.1f}s")
                        del reassemble_buffer[session_key]
                        return
                    else:
                        del blacklist[obu_id_str]

                # ─── 4. 已認證 OBU F1 軟限流 (防止惡意合法節點狂發 F1 消耗 CPU，超過 10Hz 靜默丟棄) ───
                if not check_obu_f1_rate_limit(obu_id_str, now):
                    del reassemble_buffer[session_key]
                    return

                # ─── 3. 解決每車 1 會話與重放問題：去重與新取代舊 ───
                existing_key = id_active_session.get(obu_id_str)
                if existing_key is not None and existing_key != session_key:
                    old_meta = id_session_meta.get(obu_id_str, {})
                    old_ts = old_meta.get("f1_timestamp", 0.0)

                    # 若收到相同的 F1 (相同時間戳或舊時間戳) → 視為重放攻擊/重複分片，直接忽略不開新會話
                    if f1_ts <= old_ts:
                        print(f"[安全防護 去重] 車輛 {obu_id_str} 收到重複或舊 F1 (ts={f1_ts:.3f} <= {old_ts:.3f})，忽略重複會話")
                        del reassemble_buffer[session_key]
                        return
                    else:
                        # 較新的合法 F1 到達 → 直接取代並釋放舊的未完成會話！
                        print(f"[安全防護 取代] 車輛 {obu_id_str} 傳來更新之 F1 (ts={f1_ts:.3f} > {old_ts:.3f})，主動取代舊會話")
                        if existing_key in reassemble_buffer:
                            del reassemble_buffer[existing_key]

                # 【修正】分片總數以通過認證的 F1 為準。會話可能由先到的偽造分片建立 (分片數由攻擊者決定)，
                # 原本沿用該長度，F1 回溯檢查時 IndexError → receive_data 未攔截例外，單一封包即可讓 RSU 停機。
                if session["total_frags"] != total_frags or len(session["fragments"]) != total_frags:
                    session["total_frags"] = total_frags
                    session["fragments"]   = [None] * total_frags
                session["mode"]           = "xor" if is_xor else None
                session["start_time"]     = now
                session["state"]          = "REASSEMBLING"
                session["expected_hashes"]= exp_hashes
                session["fragments"][0]   = raw_f1
                session["obu_id"]         = obu_id_str
                session["f1_timestamp"]   = f1_ts
                id_active_session[obu_id_str] = session_key
                id_session_meta[obu_id_str] = {"msg_id": msg_id, "f1_timestamp": f1_ts}
                print(f"[來自 {addr}] 車輛 {obu_id_str} F1 ECC 驗證通過，進入預備放行 (閃黃燈)，啟動 {PRUNING_TIMEOUT*1000:.0f}ms 計時器")

                # 【UDP 亂序自癒】：回溯檢查在 F1 之前就先到達並暫存的後續分片，從候選中挑出吻合承諾者
                import hashlib
                pre_f1 = session.pop("pre_f1", {})
                for s_idx in range(1, total_frags):
                    want  = exp_hashes.get(s_idx + 1)
                    cands = list(pre_f1.get(s_idx + 1, []))
                    if session["fragments"][s_idx] is not None and session["fragments"][s_idx] not in cands:
                        cands.append(session["fragments"][s_idx])
                    match = next((c for c in cands if want is not None and hashlib.sha256(c).digest() == want), None)
                    if cands and match is None:
                        # 認證前雜湊不符：丟棄偽造分片，不封鎖 obu_id (避免攻擊者隨意注入偽造分片使救護車被鎖)
                        print(f"[防 DoS 注入攔截] 暫存之分片 {s_idx+1} 雜湊不符！丟棄偽造分片！")
                    session["fragments"][s_idx] = match
                session["pre_f1"] = {}

                # 若為 XOR 模式，嘗試重組（應對 FP/後續片先到的情況）
                if session["mode"] == "xor":
                    _try_xor_recovery(session_key, session, addr, sock, rsu_id=current_rsu)
                # 【修正】DUP/一般模式：主 F1 掉包、尾端備用 F1 最後才到時，後續分片早已收齊，
                # 原本只有「收到 F2..FN」的分支會檢查是否收齊 → 會話永遠不會驗證，直到逾時被清除，
                # 備用 F1 完全失去作用。F1 到達時也要檢查是否已收齊並進入驗證。
                elif all(fragment is not None for fragment in session["fragments"]):
                    elapsed_reassembly = (time.time() - session["start_time"]) * 1000 if session["start_time"] else 0
                    print(f"[來自 {addr}] F1 最後到達，已收齊 ID為 {msg_id} 的所有分片 ({elapsed_reassembly:.2f}ms)")
                    packet = b''.join(session["fragments"])
                    _finalize_session(session_key, session, packet, addr, sock, rsu_id=current_rsu)
            else:
                # 認證前失敗 (F1 驗簽失敗)：宣稱的 obu_id 未經認證，任何人皆能填寫。
                # 僅丟棄該無效封包與會話，絕不封鎖 obu_id (徹底杜絕偽造 ID 嫁禍封鎖救護車之漏洞)！
                print(f"[來自 {addr}] F1 ECC 驗證失敗，拒絕閃黃燈，清除無效暫存 (不封鎖聲稱之 ID: {obu_id_str})")
                del reassemble_buffer[session_key]
                return
        else:
            return

    # ── 2. 收到後續分片 (F2, F3...) ──
    else:
        if seq_num < 1 or seq_num > total_frags:
            return  # 非法序號，忽略

        if session["expected_hashes"] is None:
            # F1 尚未抵達：暫存為候選，等待 F1 的雜湊承諾篩選
            _stash_pre_f1(session, seq_num, chunk_bytes)
            if session["start_time"] is None:
                session["start_time"] = time.time()   # 80ms 計時同樣適用；狀態維持 WAITING_F1 直到 F1 通過認證
            print(f"[來自 {addr}] 收到ID為 {msg_id} 的分片 ({seq_num}/{total_frags})，F1 未到，暫存待驗。")
            return

        if total_frags != session["total_frags"]:
            return  # 與已認證 F1 宣告的分片數不符，丟棄

        # 【即時防 DoS 注入攔截 (Early-Drop)】
        if session["expected_hashes"] is not None:
            import hashlib
            expected_h = session["expected_hashes"].get(seq_num)
            if expected_h is not None:
                calc_h = hashlib.sha256(chunk_bytes).digest()
                if calc_h != expected_h:
                    # 認證前雜湊不符：單純丟棄該分片，絕不封鎖 obu_id (攻擊者可任意廣播假 F2)
                    print(f"\n[防 DoS 注入攔截] 偽造分片 ({seq_num}/{total_frags})！雜湊不符，立即丟棄！")
                    return

        session["fragments"][seq_num - 1] = chunk_bytes
        if session["start_time"] is None:
            session["start_time"] = time.time()
            session["state"] = "REASSEMBLING"

        print(f"[來自 {addr}] 收到ID為 {msg_id} 的分片 ({seq_num}/{total_frags})。")

        if session["mode"] == "xor":
            _try_xor_recovery(session_key, session, addr, sock, rsu_id=current_rsu)
        else:
            # 檢查 DUP 模式是否收齊
            if all(fragment is not None for fragment in session["fragments"]):
                elapsed_reassembly = (time.time() - session["start_time"]) * 1000 if session["start_time"] else 0
                print(f"[來自 {addr}] 已收齊 ID為 {msg_id} 的所有分片 ({elapsed_reassembly:.2f}ms)")
                packet = b''.join(session["fragments"])
                _finalize_session(session_key, session, packet, addr, sock, rsu_id=current_rsu)

def receive_data(sock):
    sock.settimeout(SOCKET_TIMEOUT)  # 設定 Non-blocking 輪詢超時
    last_prune = 0.0
    try:
        while True:
            try:
                data, addr = sock.recvfrom(BUFFER_SIZE)
                process_fragment(data, addr, sock=sock)
            except socket.timeout:
                pass  # 正常超時，繼續執行
            except Exception as e:
                # 【修正】任何單一封包觸發的例外都不可讓 RSU 主迴圈停機 (原本未攔截，畸形封包即可 DoS)
                print(f"[錯誤] 處理封包時發生例外，已丟棄該封包：{type(e).__name__}: {e}")
            # 檢查是否有超時分片需要清理 (最多每 PRUNE_INTERVAL 一次)
            if time.time() - last_prune >= PRUNE_INTERVAL:
                prune_expired_sessions()
                last_prune = time.time()

    except KeyboardInterrupt:
        print("\nRSU 已手動關閉")
    finally:
        sock.close()

if __name__ == "__main__":
    # (REmote CA)建立 UDP Socket 
    # socket.AF_INET 代表使用 IPv4
    # socket.SOCK_DGRAM 代表使用 UDP 協議
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # 將 Socket 綁定到 IP 與 Port
    sock.bind((RSU_IP, RSU_PORT))
    print(f"RSU啟動，正在監聽 {RSU_PORT}")
    receive_data(sock)