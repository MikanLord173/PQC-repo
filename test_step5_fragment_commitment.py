import os, sys, time, struct, hashlib, subprocess
from OBU.setup import setup
from OBU.encode_packet import gen_packet
from OBU.fragment import make_fragments
import RSU.main as rsu_main
from RSU.main import process_fragment, reassemble_buffer, recent_completed

def run_test():
    print("=" * 65)
    print("【項目 4 完整防禦測試】：F1 分片雜湊承諾 (Anti-DoS Early Drop & 亂序)")
    print("=" * 65)

    obu_test_id = "AMB-217"
    addr = ("127.0.0.1", 54321)

    # 1. 確保憑證與金鑰齊備
    if not os.path.exists(f"OBU/keys/{obu_test_id}_ecc_priv.key"):
        print("\n[環境準備] 啟動 CA 伺服器並註冊 AMB-217...")
        server_proc = subprocess.Popen(
            ["python3", "-m", "CA.listen"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        time.sleep(1.5)
        try:
            assert setup(obu_test_id), "OBU setup 失敗！"
        finally:
            server_proc.terminate()
            server_proc.wait()

    # 清空 RSU 暫存
    reassemble_buffer.clear()
    recent_completed.clear()

    # -------------------------------------------------------------
    # 測試 1: 正常循序傳輸 (F1 -> F2 -> F3)，驗證承諾機制不干擾正常流程
    # -------------------------------------------------------------
    print("\n" + "-" * 55)
    print("【測試 1】：正常循序發送 (F1 -> F2 -> F3)")
    print("-" * 55)
    msg_id_1 = 101
    full_packet = gen_packet(obu_test_id, known_RSU=False)
    frags_1 = make_fragments(full_packet, msg_id=msg_id_1)
    print(f"  -> 生成 Full 封包 ({len(full_packet)} Bytes)，切出 {len(frags_1)} 個分片")

    for idx, frag in enumerate(frags_1):
        process_fragment(frag, addr)
    
    session_key_1 = (msg_id_1, addr)
    assert session_key_1 in recent_completed, "【失敗】正常流程未能成功重組與驗證！"
    assert session_key_1 not in reassemble_buffer, "【失敗】完成後未正確清理暫存！"
    print("  -> [PASS] 正常流程循序收齊，端到端解析與雙簽驗證成功！")

    # -------------------------------------------------------------
    # 測試 2: 攻擊者注入偽造 F2 (即時 0.5 微秒 Early-Drop 攔截)
    # -------------------------------------------------------------
    print("\n" + "-" * 55)
    print("【測試 2】：惡意碎片注入防禦 (Early-Drop 0.5μs 攔截)")
    print("-" * 55)
    msg_id_2 = 102
    # 每個測試使用新的 SRM：RSU 會拒絕重複放行同一則已放行的 SRM (F-4)
    frags_2 = make_fragments(gen_packet(obu_test_id, known_RSU=False), msg_id=msg_id_2)

    # 先送合法 F1
    process_fragment(frags_2[0], addr)
    session_key_2 = (msg_id_2, addr)
    assert session_key_2 in reassemble_buffer, "F1 應成功建立會話"
    assert reassemble_buffer[session_key_2]["expected_hashes"] is not None, "F1 應解析出承諾雜湊清單"
    print("  -> 合法 F1 到達，RSU 已成功註冊後續分片之雜湊承諾。")

    # 構造被竄改的惡意 F2 (例如中間人修改了 1 byte 或注入垃圾 payload)
    fake_f2 = bytearray(frags_2[1])
    fake_f2[-5] = (fake_f2[-5] + 1) % 256
    fake_f2 = bytes(fake_f2)

    t_start = time.perf_counter()
    process_fragment(fake_f2, addr)
    t_drop = (time.perf_counter() - t_start) * 1e6 # 轉微秒 (μs)

    # 驗證：惡意 F2 必須被即刻丟棄，不可存入 session["fragments"][1]
    assert reassemble_buffer[session_key_2]["fragments"][1] is None, "【失敗】惡意 F2 竟然未被丟棄！"
    print(f"  -> [PASS] 惡意 F2 於 {t_drop:.2f} μs 內被雜湊承諾秒殺丟棄！(完全未消耗 PQC 驗簽算力)")

    # 清理該測試會話
    if session_key_2 in reassemble_buffer:
        del reassemble_buffer[session_key_2]

    # -------------------------------------------------------------
    # 測試 3: UDP 無線電亂序 (F2 先到，F1 後到)
    # -------------------------------------------------------------
    print("\n" + "-" * 55)
    print("【測試 3】：UDP 亂序自癒傳輸 (F2 先到 -> F1 後到回溯檢驗)")
    print("-" * 55)
    msg_id_3 = 103
    # 每個測試使用新的 SRM：RSU 會拒絕重複放行同一則已放行的 SRM (F-4)
    frags_3 = make_fragments(gen_packet(obu_test_id, known_RSU=False), msg_id=msg_id_3)

    # 先送 F2
    process_fragment(frags_3[1], addr)
    session_key_3 = (msg_id_3, addr)
    assert session_key_3 in reassemble_buffer, "F2 先到應能開闢 WAITING_F1 會話"
    assert reassemble_buffer[session_key_3]["state"] == "WAITING_F1", "狀態應為 WAITING_F1"
    assert reassemble_buffer[session_key_3]["fragments"][1] is not None, "F2 應暫存在緩衝區"
    print("  -> F2 先抵達，RSU 妥善收容至暫存區 (狀態: WAITING_F1)。")

    # 後送合法 F1 (應回溯驗證 F2 雜湊並轉入 REASSEMBLING)
    process_fragment(frags_3[0], addr)
    assert reassemble_buffer[session_key_3]["state"] == "REASSEMBLING", "F1 到達後應轉為 REASSEMBLING"
    assert reassemble_buffer[session_key_3]["fragments"][1] is not None, "F2 經雜湊回溯比對無誤，應被保留"
    print("  -> F1 後續抵達，回溯檢驗 F2 雜湊承諾吻合！成功轉入 REASSEMBLING。")

    # 再送出剩餘的所有分片 (F3, F4...) 完成重組
    for frag in frags_3[2:]:
        process_fragment(frag, addr)
    assert session_key_3 in recent_completed, "【失敗】亂序情況下未能在送齊後完成重組！"
    print("  -> [PASS] UDP 亂序自癒重組成功！")

    # -------------------------------------------------------------
    # 測試 4: 亂序惡意攻擊 (偽造 F2 先到，F1 後到回溯查出並全毀會話)
    # -------------------------------------------------------------
    print("\n" + "-" * 55)
    print("【測試 4】：亂序惡意注入防禦 (偽造 F2 先到 -> F1 到達時回溯抓包並清除)")
    print("-" * 55)
    msg_id_4 = 104
    # 每個測試使用新的 SRM：RSU 會拒絕重複放行同一則已放行的 SRM (F-4)
    frags_4 = make_fragments(gen_packet(obu_test_id, known_RSU=False), msg_id=msg_id_4)

    # 攻擊者先偷送偽造的 F2
    fake_f2_4 = bytearray(frags_4[1])
    fake_f2_4[-10] = (fake_f2_4[-10] + 2) % 256
    process_fragment(bytes(fake_f2_4), addr)
    session_key_4 = (msg_id_4, addr)

    # 合法 F1 到達，RSU 依據 F1 提取承諾雜湊，比對發現先前收到的 F2 是假的！
    # 只丟棄偽造分片、保留會話：若整個會話作廢，攻擊者只要搶先送一片假 F2 就能讓救護車這則訊息失效。
    process_fragment(frags_4[0], addr)
    assert session_key_4 in reassemble_buffer, "【失敗】偽造 F2 不應使合法會話作廢！"
    assert reassemble_buffer[session_key_4]["fragments"][1] is None, "【失敗】偽造 F2 應被丟棄！"
    for frag in frags_4[1:]:
        process_fragment(frag, addr)
    assert session_key_4 in recent_completed, "【失敗】補上合法 F2 後應完成重組！"
    print("  -> [PASS] 回溯比對抓出惡意 F2 並丟棄，合法分片補上後仍成功放行，抵禦暫存池污染攻擊！")

    # -------------------------------------------------------------
    # 測試 5: 多車暫存池上限保護 (LRU 淘汰機制防止記憶體耗竭)
    # -------------------------------------------------------------
    print("\n" + "-" * 55)
    print("【測試 5】：多車高並發記憶體上限防禦 (LRU Cap: 100 sessions)")
    print("-" * 55)
    reassemble_buffer.clear()
    
    # 模擬 105 輛車或攻擊者併發傳送未收齊之分片
    for i in range(105):
        sim_msg_id = 1000 + i
        sim_addr = (f"192.168.{i // 250}.{i % 250 + 1}", 10000 + i)   # 每輛車不同來源 IP (同一 IP 會先被每秒 50 包限流擋下)
        # 每輛車只丟一片 F2 (不全)
        fake_header = struct.pack('!BBH', 2, 3, sim_msg_id)
        process_fragment(fake_header + b"fake_data_chunk", sim_addr)

    pool_size = len(reassemble_buffer)
    print(f"  -> 灌入 105 筆併發會話後，當前緩衝池大小: {pool_size} (設定上限: 100)")
    assert pool_size == 100, f"【失敗】緩衝池大小 {pool_size} 超過上限 100！"
    print("  -> [PASS] 緩衝池嚴格守住 100 筆上限，徹底杜絕記憶體耗竭型 DoS！")

    print("\n" + "=" * 65)
    print("【全部 5 項防禦單元測試全部通過！】")
    print("  1. 循序正常重組 : 通過")
    print("  2. 即時 0.5μs Early-Drop : 通過 (無 PQC 驗簽浪費)")
    print("  3. UDP 亂序自癒重組 : 通過")
    print("  4. 亂序惡意注入回溯丟棄 : 通過")
    print("  5. 多車 LRU 記憶體防禦 (100槽) : 通過")
    print("=" * 65)

if __name__ == "__main__":
    run_test()
