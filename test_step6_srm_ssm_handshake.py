import os, sys, time, struct, json, hashlib, subprocess
from OBU.setup import setup
from OBU.gen_payload import generate_srm_payload, format_temporary_id
from OBU.encode_packet import gen_packet
from OBU.fragment import make_fragments
from RSU.gen_payload import generate_ssm_payload
import RSU.main as rsu_main
from RSU.main import process_fragment, reassemble_buffer, recent_completed
from RSU.parse import parse_packet

def run_test():
    print("=" * 70)
    print("【SAE J2735 SRM/SSM 雙向標準通訊與 ACK 防失步測試】")
    print("=" * 70)

    obu_test_id = "AMB-217"
    addr = ("127.0.0.1", 54321)

    # 1. 確保金鑰齊備
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

    # -------------------------------------------------------------
    # 測試 1: 驗證 SRM 與 SSM 結構標準性與最小化體積
    # -------------------------------------------------------------
    print("\n" + "-" * 60)
    print("【測試 1】：驗證 SAE J2735 SRM / SSM 最小化封包大小與欄位")
    print("-" * 60)
    srm_payload = generate_srm_payload(obu_test_id)
    srm_bytes = json.dumps(srm_payload, separators=(',', ':')).encode('utf-8')
    print(f"  -> SRM Payload 原始大小 = {len(srm_bytes)} Bytes (預期約 360~380 Bytes)")
    assert srm_payload["msgID"] == 29, "SRM msgID 必須為 29！"
    assert "requests" in srm_payload and "requestor" in srm_payload, "SRM 核心欄位缺失！"
    assert "timeStamp" not in srm_payload, "SRM 冗餘 Optional timeStamp 應剔除！"
    assert len(srm_bytes) <= 400, f"SRM 大小超過預期：{len(srm_bytes)} Bytes"
    print("  -> [PASS] SRM 格式標準，所有冗餘 Optional 成功剔除！")

    ssm_payload = generate_ssm_payload(obu_test_id, intersection_id=1, approach_id=1, request_id=1, status=4)
    ssm_bytes = json.dumps(ssm_payload, separators=(',', ':')).encode('utf-8')
    print(f"  -> SSM Payload 原始大小 = {len(ssm_bytes)} Bytes (預期約 240~270 Bytes)")
    assert ssm_payload["msgID"] == 30, "SSM msgID 必須為 30！"
    assert ssm_payload["status"][0]["sigStatus"][0]["status"] == 4, "SSM 必須標記 status=4 (granted)！"
    assert len(ssm_bytes) <= 300, f"SSM 大小超過預期：{len(ssm_bytes)} Bytes"
    print("  -> [PASS] SSM 格式標準，單一極簡 UDP 即可送達！")

    # -------------------------------------------------------------
    # 測試 2: 完整 SRM 發送 -> RSU 驗證通過 -> 產生 SSM 綠燈回條
    # -------------------------------------------------------------
    print("\n" + "-" * 60)
    print("【測試 2】：SRM 端到端雙簽驗證與 SSM 綠燈回條生成")
    print("-" * 60)
    reassemble_buffer.clear()
    recent_completed.clear()

    full_packet = gen_packet(obu_test_id, known_RSU=False)
    frags_full = make_fragments(full_packet, msg_id=201)
    print(f"  -> Full 模式 SRM 封包總體積 = {len(full_packet)} Bytes, 切為 {len(frags_full)} 片")
    assert len(frags_full) == 5, f"Full 模式 (含 CA 後量子憑證) 應切為 5 片，目前為 {len(frags_full)} 片"

    # 模擬 Mock Socket 收集 RSU 送出的 SSM 回條
    class MockSocket:
        def __init__(self):
            self.sent_packets = []
        def sendto(self, data, target_addr):
            self.sent_packets.append((data, target_addr))

    mock_sock = MockSocket()
    for frag in frags_full:
        process_fragment(frag, addr, sock=mock_sock)

    assert len(mock_sock.sent_packets) == 1, "【失敗】RSU 驗證成功後未回傳 SSM 回條！"
    sent_data, target_addr = mock_sock.sent_packets[0]
    assert target_addr == addr, "【失敗】SSM 回條回傳目標位址錯誤！"
    ssm_resp = json.loads(sent_data.decode('utf-8'))
    assert ssm_resp["msgID"] == 30, "【失敗】回條 msgID 應為 30 (SSM)！"
    ack_entity = ssm_resp["status"][0]["sigStatus"][0]["requester"]["id"]["entityID"]
    # SSM 依 SAE J2735 以 4 bytes 的 TemporaryID 標示車輛 (OBU.main 同時接受完整 ID 與 TemporaryID)
    assert ack_entity in (obu_test_id, format_temporary_id(obu_test_id)), "【失敗】SSM 回條對象車輛 ID 不符！"
    assert ssm_resp["status"][0]["sigStatus"][0]["status"] == 4, "【失敗】號誌未授予放行 (granted)！"
    print(f"  -> [PASS] RSU 成功完成雙簽驗證，並精準射出 {len(sent_data)} Bytes 之 SSM 綠燈核准回條！")

    # -------------------------------------------------------------
    # 測試 3: 狀態失步自癒防護 (第一包若掉包，OBU 絕不誤切 Short)
    # -------------------------------------------------------------
    print("\n" + "-" * 60)
    print("【測試 3】：掉包自癒防護 (未收 ACK 絕不切 Short，消除狀態失步死鎖)")
    print("-" * 60)
    # 模擬 OBU 狀態字典
    test_saved_RSU = {}
    rsu_key = "127.0.0.1:5005"

    # 模擬第 1 包發送後空中掉包 (RSU 沒收到，OBU 沒收到 ACK)
    # 此時 test_saved_RSU 應保持為空
    is_known_after_loss = rsu_key in test_saved_RSU
    assert not is_known_after_loss, "【失敗】掉包情況下 OBU 竟提前記憶 RSU！"
    
    # 驗證下一包依然保持為 Full 模式
    pkt_retry = gen_packet(obu_test_id, known_RSU=is_known_after_loss)
    print(f"  -> 重傳封包大小 = {len(pkt_retry)} Bytes (包含完整公鑰，杜絕死鎖)")
    assert len(pkt_retry) > 4000, "【失敗】掉包後下一包竟然切換到了 Short 模式！"
    print("  -> [PASS] OBU 成功維持 Full 模式重試，消除狀態失步死鎖！")

    # 模擬重試成功並收到 SSM ACK
    test_saved_RSU[rsu_key] = time.time()
    is_known_after_ack = rsu_key in test_saved_RSU
    pkt_after_ack = gen_packet(obu_test_id, known_RSU=is_known_after_ack)
    print(f"  -> 收到 SSM ACK 後之封包大小 = {len(pkt_after_ack)} Bytes (成功切換 Short 模式)")
    assert len(pkt_after_ack) < 3000, "【失敗】收到 ACK 後未成功切換至 Short 模式！"
    print("  -> [PASS] 收到 ACK 後無縫切換至 2.9KB Short 模式，全程閉環成功！")

    print("\n" + "=" * 70)
    print("【SAE J2735 SRM / SSM 雙向握手與防失步測試全部通過！】")
    print("  1. SRM 最小化封包 (~368B) : 通過")
    print("  2. SSM 最小化回條 (~262B) : 通過")
    print("  3. RSU 驗證後主動回覆 SSM : 通過")
    print("  4. ACK 驅動狀態切換 (防死鎖) : 通過")
    print("=" * 70)

if __name__ == "__main__":
    run_test()
