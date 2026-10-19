import socket, time, os
import RSU.parse as parse

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

# ─── 下游拓樸鄰居表（Topology Lookup Table） ──────────────────────────────────
# 定義幹道路口有向圖：{當前路口ID: {方向/進口道: [下游RSU清單], "default": [下游RSU清單]}}
DOWNSTREAM_TOPOLOGY = {
    1: {"eastbound": [2, 3], "northbound": [4], "default": [2, 3]},
    2: {"eastbound": [3], "default": [3]},
    3: {"eastbound": [4], "default": [4]},
    4: {"default": []}
}

def get_downstream_rsus(current_id: int, srm_data: dict = None) -> list:
    """根據拓樸圖與車輛 SRM 行駛資訊查出下游路口清單"""
    topo = DOWNSTREAM_TOPOLOGY.get(current_id, {})
    if isinstance(topo, list):
        return list(topo)
    return list(topo.get("default", []))

def trigger_inter_rsu_prewarm(current_rsu_id: int, obu_id_raw: bytes, P_U_bytes: bytes,
                              vk_ecc, obu_pqc_pub: bytes, srm_data: dict = None,
                              rsu_cluster: dict = None) -> list:
    """
    路側有線骨幹 (Backhaul) 主動預同步：
    當 RSU 完成雙簽驗證後，透過有線骨幹網路將 (Q_U, PK_PQC, ETA) 主動注入下游路口。
    下游路口免算點乘重構，實現零冷啟動！
    """
    downstream_ids = get_downstream_rsus(current_rsu_id, srm_data)
    if not downstream_ids:
        return []

    # 計算預估抵達時間 (ETA) 與快取過期時間 (TTL)
    # 預設行駛 300 公尺 / 速度 60km/h (16.6m/s) ≈ 18 秒後抵達
    eta = 18.0
    if srm_data:
        pos = srm_data.get("requestor", {}).get("position", {})
        speed_raw = pos.get("speed", {}).get("speed", 0)
        speed_mps = speed_raw * 0.02
        if speed_mps > 2.0:
            eta = 300.0 / speed_mps

    expire_at = time.time() + eta + 30.0  # 給予 30 秒寬限期
    prewarmed_list = []

    for target_id in downstream_ids:
        if rsu_cluster and target_id in rsu_cluster:
            target_rsu = rsu_cluster[target_id]
            target_rsu.inject_prewarm(obu_id_raw, P_U_bytes, vk_ecc, obu_pqc_pub, expire_at)
        else:
            parse.inject_prewarm_cache(target_id, obu_id_raw, P_U_bytes, vk_ecc, obu_pqc_pub, expire_at)
        prewarmed_list.append(target_id)
        print(f"  [有線骨幹預同步] 已將已驗證金鑰 (Q_U, PK_PQC) 推送至下游路口 {target_id} (TTL: {eta+30:.0f}s)")

    return prewarmed_list

# ─── 方案A：Per-ID Quota & Sliding Blacklist 配置 ──────────────────────────
PER_ID_TIMEOUT_THRESHOLD = 3     # 某 ID 在 BLACKLIST_WINDOW 秒內超時 N 次 → 封鎖
BLACKLIST_WINDOW     = 10.0     # 滑動視窗長度（秒）
BLACKLIST_DURATION   = 30.0     # 封鎖持續時間（秒）
# ──────────────────────────────────────────────────────────────────────────

# 重組緩衝區，key= (msg_id, addr)
# value 為 session dict: {"state": ..., "start_time": ..., "total_frags": ..., "fragments": [...], "created_at": ..., "obu_id": ...}
reassemble_buffer = {}

# 最近已完成重組的 (msg_id, addr)，避免尾巴重複分片再次觸發新 session
recent_completed = {}

# ─── 方案A：Per-ID 活躍 session 索引 & Sliding Blacklist ──────────────────
# id_active_session[obu_id] = session_key  →  快速查詢該 ID 當前佔用的 session
id_active_session = {}

# id_timeout_log[obu_id] = [timestamp, ...]  →  滑動視窗超時紀錄
id_timeout_log = {}

# blacklist[obu_id] = ban_until_timestamp
blacklist = {}
# ──────────────────────────────────────────────────────────────────────────

# ─── 方案A 輔助：將某 obu_id 的超時紀錄加入滑動視窗，必要時封鎖 ────────────
def _record_timeout_and_maybe_blacklist(obu_id: str, now: float):
    """記錄一次該 obu_id 的超時事件，若在 BLACKLIST_WINDOW 內超時次數超過門檻，封鎖之。"""
    log = id_timeout_log.setdefault(obu_id, [])
    # 滑動：清除視窗外的舊事件
    log[:] = [t for t in log if now - t < BLACKLIST_WINDOW]
    log.append(now)

    if len(log) >= PER_ID_TIMEOUT_THRESHOLD:
        ban_until = now + BLACKLIST_DURATION
        blacklist[obu_id] = ban_until
        log.clear()  # 重置計數，避免反覆加成
        print(f"[方案A ⚠ 黑名單] 車輛 ID={obu_id} 在 {BLACKLIST_WINDOW:.0f}s 內")
        print(f"  連續超時 {PER_ID_TIMEOUT_THRESHOLD} 次（疑似惡意節點送不完整分片耗盡記憶體）")
        print(f"  → 封鎖 {BLACKLIST_DURATION:.0f}s，直至 {time.strftime('%H:%M:%S', time.localtime(ban_until))}\n")

# 定時檢查
def prune_expired_sessions():
    now = time.time()
    # 清理超過 2 秒的已完成紀錄
    for key, done_time in list(recent_completed.items()):
        if now - done_time > 2.0:
            del recent_completed[key]

    # 清理已過期的黑名單條目
    for obu_id in list(blacklist.keys()):
        if now >= blacklist[obu_id]:
            del blacklist[obu_id]
            print(f"[方案A] 車輛 ID={obu_id} 黑名單已解除")

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
        obu_id = session.get("obu_id")  # 可能為 None（F1 尚未到達時）
        print(f"\n[超時清理] 訊息 ID={msg_id} [來自 {addr}] 逾時 ({elapsed*1000:.1f}ms > {PRUNING_TIMEOUT*1000:.0f}ms) 碎片不齊")
        print(f"清空快取，號誌維持正常週期")
        del reassemble_buffer[key]

        # 方案A：清理 Per-ID 活躍 session 索引
        if obu_id and id_active_session.get(obu_id) == key:
            del id_active_session[obu_id]

        # 方案A：記錄超時、判斷是否需要封鎖
        if obu_id:
            _record_timeout_and_maybe_blacklist(obu_id, now)
        else:
            # F1 根本沒通過驗證就超時 → 亦計入警告（addr 作為匿名 key）
            _record_timeout_and_maybe_blacklist(str(addr), now)
            print(f"  [方案A] 匿名來源 {addr} 超時（F1 未通過驗證），計入警告視窗\n")
        print()

# ─── 共用：重組完成後的密碼驗證與 SSM 回條（DUP 與 XOR 兩個路徑共用）─────────
def _finalize_session(session_key, session, packet, addr, sock, rsu_id=None):
    """封包重組完成後，清理緩衝區並執行密碼驗證→放行流程。"""
    current_rsu = rsu_id if rsu_id is not None else RSU_ID
    del reassemble_buffer[session_key]
    recent_completed[session_key] = time.time()
    # 方案A：成功完成 → 清除 Per-ID 活躍 session 索引（正常完成不計超時）
    obu_id_done = session.get("obu_id")
    if obu_id_done and id_active_session.get(obu_id_done) == session_key:
        del id_active_session[obu_id_done]

    payload = parse.parse_packet(packet, rsu_id=current_rsu)
    if payload:
        total_latency = time.time() - payload['full_timestamp']
        if total_latency > 0.15:
            print(f"\n[逾期] 封包總延遲 ({total_latency*1000:.1f}ms > 150ms)，疑似重放攻擊！")
            print(f"拒絕放行，號誌維持正常週期\n")
            return

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
                    srm_data=payload
                )

            if sock is not None:
                import json
                from RSU.gen_payload import generate_ssm_payload
                ssm_payload = generate_ssm_payload(
                    obu_id=req_id,
                    intersection_id=inter_id,
                    approach_id=approach_id,
                    request_id=req_num,
                    status=4,
                    sequence_number=payload.get("sequenceNumber", 1),
                    prewarmed_rsus=prewarmed_rsus
                )
                ssm_bytes = json.dumps(ssm_payload, separators=(',', ':')).encode('utf-8')
                sock.sendto(ssm_bytes, addr)
                print(f"  -> 已向車輛 {req_id} 回傳 SAE J2735 SSM 放行回條 (ACK, {len(ssm_bytes)} bytes)")
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
        # ─── 悲觀降級：若為 Short 模式 Cache Miss，回傳 status=6 (Need Cert / Fallback) ───
        if parse.LAST_PARSE_STATUS == "NEED_CERT" and sock is not None:
            import json
            from RSU.gen_payload import generate_ssm_payload
            nack_payload = generate_ssm_payload(
                obu_id=session.get("obu_id", "AMB-217"),
                intersection_id=current_rsu,
                status=6
            )
            nack_bytes = json.dumps(nack_payload, separators=(',', ':')).encode('utf-8')
            sock.sendto(nack_bytes, addr)
            print(f"  -> 已向車輛發送 Fast-NACK (status=6，要求補憑證退回 Full 模式重試)\n")


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
    parity      = session["xor_parity_payload"]
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
    if n_recv_heavy == n_heavy - 1 and parity is not None:
        from fec import recover_xor_heavy
        missing_idx = next(i for i in range(n_heavy) if i not in received_heavy)
        missing_seq = missing_idx + 2
        packet = recover_xor_heavy(received_heavy, parity, n_heavy, f1_raw)
        if packet is None:
            print(f"[XOR] 修復計算失敗（長度不符），繼續等待")
            return
        elapsed = (time.time() - session["start_time"]) * 1000 if session["start_time"] else 0
        print(f"[XOR 修復成功] 來自 {addr}，F{missing_seq}/{total_frags} 已還原 ({elapsed:.1f}ms)，進行密碼驗證")
        _finalize_session(session_key, session, packet, addr, sock, rsu_id=current_rsu)


# 處理收到的分片
def process_fragment(data, addr, sock=None, rsu_id=None):
    current_rsu = rsu_id if rsu_id is not None else RSU_ID
    header_bytes = data[:4]
    chunk_bytes  = data[4:]
    # parse_header 現在回傳 4-tuple（is_xor 旗標由 total_frags byte 高位元決定）
    seq_num, total_frags, msg_id, is_xor = parse.parse_header(header_bytes)
    if seq_num is None:
        print(f"[來自 {addr}] 收到無效的 header")
        return

    session_key = (msg_id, addr)

    # 若該訊息剛重組完成，忽略後續抵達的重複分片 (如尾巴備用 F1)
    if session_key in recent_completed:
        return

    # 多車暫存池上限保護 (上限 100 台並發車輛，約 400KB 記憶體)
    if session_key not in reassemble_buffer:
        if len(reassemble_buffer) >= 100:
            oldest_key = min(reassemble_buffer.keys(), key=lambda k: reassemble_buffer[k]["created_at"])
            del reassemble_buffer[oldest_key]

        reassemble_buffer[session_key] = {
            "state"            : "WAITING_F1",
            "mode"             : "xor" if is_xor else None,  # 從第一片就確認模式
            "start_time"       : None,
            "total_frags"      : total_frags,
            "fragments"        : [None] * total_frags,
            "expected_hashes"  : None,
            "xor_parity_payload": None,
            "created_at"       : time.time(),
            "obu_id"           : None,   # 方案A：DUP/XOR 模式 F1 驗證後填入
        }
    session = reassemble_buffer[session_key]
    # 若後續分片帶有 XOR 旗標，補充標記（應對 parity 先到的情況）
    if is_xor:
        session["mode"] = "xor"

    # ── seq_num == 0：XOR 修復分片 FP ──
    if seq_num == 0:
        if session["xor_parity_payload"] is None:
            session["xor_parity_payload"] = chunk_bytes
            if session["start_time"] is None:
                session["start_time"] = time.time()
                session["state"] = "REASSEMBLING"
            print(f"[XOR] 來自 {addr} 收到修復分片 FP ({len(chunk_bytes)}B)")
            _try_xor_recovery(session_key, session, addr, sock, rsu_id=current_rsu)
        return

    # ── 1. 收到 F1 碎片 (首分片) ──
    if seq_num == 1:
        if session["fragments"][0] is None:
            f1_valid, obu_id_str, _, exp_hashes, raw_f1 = parse.verify_f1_ecc(chunk_bytes, rsu_id=current_rsu)
            if f1_valid:
                now = time.time()

                # ─── 方案A：黑名單檢查 ────────────────────────────────────────
                if obu_id_str in blacklist:
                    ban_until = blacklist[obu_id_str]
                    if now < ban_until:
                        remaining = ban_until - now
                        print(f"[方案A 拒絕] 車輛 {obu_id_str} 在黑名單中，剩餘封鎖 {remaining:.1f}s")
                        del reassemble_buffer[session_key]
                        return
                    else:
                        del blacklist[obu_id_str]

                # ─── 方案A：Per-ID Quota 檢查 ─────────────────────────────────
                existing_key = id_active_session.get(obu_id_str)
                if existing_key is not None and existing_key != session_key:
                    if existing_key in reassemble_buffer:
                        print(f"[方案A Quota] 車輛 {obu_id_str} 已有活躍 session，拒絕第二個")
                        del reassemble_buffer[session_key]
                        return
                    else:
                        del id_active_session[obu_id_str]

                session["start_time"]     = now
                session["state"]          = "REASSEMBLING"
                session["expected_hashes"]= exp_hashes
                session["fragments"][0]   = raw_f1
                session["obu_id"]         = obu_id_str
                id_active_session[obu_id_str] = session_key
                print(f"[來自 {addr}] 車輛 {obu_id_str} F1 ECC 驗證通過，進入預備放行 (閃黃燈)，啟動 {PRUNING_TIMEOUT*1000:.0f}ms 計時器")

                # 【UDP 亂序自癒】：回溯檢查在 F1 之前就先到達並暫存的後續分片
                import hashlib
                for s_idx in range(1, total_frags):
                    frag_data = session["fragments"][s_idx]
                    if frag_data is not None and s_idx + 1 in exp_hashes:
                        calc_h = hashlib.sha256(frag_data).digest()
                        if calc_h != exp_hashes[s_idx + 1]:
                            print(f"[防 DoS 注入攔截] 先前暫存之分片 {s_idx+1} 雜湊不符！清除惡意會話！")
                            del reassemble_buffer[session_key]
                            if id_active_session.get(obu_id_str) == session_key:
                                del id_active_session[obu_id_str]
                            return

                # 若為 XOR 模式，嘗試重組（應對 FP/後續片先到的情況）
                if session["mode"] == "xor":
                    _try_xor_recovery(session_key, session, addr, sock, rsu_id=current_rsu)
            else:
                print(f"[來自 {addr}] F1 ECC 驗證失敗，拒絕閃黃燈，清除暫存")
                del reassemble_buffer[session_key]
                return
        else:
            return

    # ── 2. 收到後續分片 (F2, F3...) ──
    else:
        if seq_num < 1 or seq_num > total_frags:
            return  # 非法序號，忽略

        # 【即時防 DoS 注入攔截 (Early-Drop)】
        if session["expected_hashes"] is not None:
            import hashlib
            expected_h = session["expected_hashes"].get(seq_num)
            if expected_h is not None:
                calc_h = hashlib.sha256(chunk_bytes).digest()
                if calc_h != expected_h:
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
    try:
        while True:
            try:
                data, addr = sock.recvfrom(BUFFER_SIZE)
                process_fragment(data, addr, sock=sock)
            except socket.timeout:
                pass  # 正常超時，繼續執行
            # 檢查是否有超時分片需要清理
            prune_expired_sessions()

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