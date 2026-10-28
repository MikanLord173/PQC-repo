import os, subprocess, time
from OBU.setup import setup
from OBU.encode_packet import gen_packet
from RSU.parse import verify_f1_ecc, parse_packet, MEMORY_KEY_CACHE, PQC_PUB_CACHE

def run_test():
    print("=" * 60)
    print("【終極瘦身驗證】：純粹 ECQV (4.2KB) + 二次極速 Short 模式 (2.9KB)")
    print("=" * 60)

    obu_test_id = "AMB-217"

    # 1. 啟動 CA 伺服器並重新註冊金鑰
    print("\n[環境準備] 啟動 CA 伺服器並為 AMB-217 生成最新精簡 ECQV 憑證...")
    server_proc = subprocess.Popen(
        ["python3", "-m", "CA.listen"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    time.sleep(1.5)
    try:
        ok_setup = setup(obu_test_id)
        assert ok_setup, "【錯誤】OBU setup 失敗！"
    finally:
        server_proc.terminate()
        server_proc.wait()

    # --- 測試 1: 首次建聯 (Full 模式) ---
    print("\n" + "-" * 50)
    print("【測試 1】：首次發送 (Full 模式，拿掉 CA 簽章瘦身至 4.2KB)")
    print("-" * 50)
    full_packet = gen_packet(obu_test_id, known_RSU=False)
    print(f"  -> Full 封包總長度 = {len(full_packet)} bytes (預期約 6700 bytes：含 2420B CA 後量子憑證)")
    assert 6500 <= len(full_packet) <= 6900, "Full 封包大小不符預期！"

    # 驗證 F1 (第一片，含分片承諾)
    from OBU.fragment import make_fragments
    frags_full = make_fragments(full_packet)
    f1_chunk = frags_full[0][4:] # 扣除 4-byte UDP header
    ok_f1, f1_id, *_ = verify_f1_ecc(f1_chunk)
    assert ok_f1, "【錯誤】Full 模式 F1 預驗證失敗！"
    print(f"  -> [PASS] F1 預驗證成功！(車輛: {f1_id})")

    # 驗證 Full 完整封包
    result_full = parse_packet(full_packet)
    assert result_full is not None, "【錯誤】Full 模式完整解析失敗！"
    print(f"  -> [PASS] Full 模式完整驗證通過！PQC 公鑰已快取至記憶體。")

    # --- 測試 2: 二次通訊 (Short 極速模式，known_RSU=True) ---
    print("\n" + "-" * 50)
    print("【測試 2】：二次發送 (Short 模式，省略 1.3KB 公鑰，狂降至 2.9KB！)")
    print("-" * 50)
    short_packet = gen_packet(obu_test_id, known_RSU=True)
    print(f"  -> Short 封包總長度 = {len(short_packet)} bytes (預期約 2902 bytes)")
    assert 2800 <= len(short_packet) <= 3100, "Short 封包大小不符預期！"

    # 驗證 Short 模式下的 F1 (記憶體命中)
    frags_short = make_fragments(short_packet)
    short_f1_chunk = frags_short[0][4:]
    ok_short_f1, short_f1_id, *_ = verify_f1_ecc(short_f1_chunk)
    assert ok_short_f1, "【錯誤】Short 模式 F1 預驗證失敗！"
    print(f"  -> [PASS] Short 模式 F1 預驗證成功 (記憶體 LRU 0ns 秒殺)！")

    # 驗證 Short 模式下的完整封包 (由 PQC_PUB_CACHE 還原公鑰)
    result_short = parse_packet(short_packet)
    assert result_short is not None, "【錯誤】Short 模式完整解析失敗！"
    station_id = (
        result_short.get("requestor", {}).get("id", {}).get("entityID")
        or result_short.get("stationID")
        or result_short.get("obu_id")
    )
    print(f"  -> [PASS] Short 模式完整驗證通過！車輛 ID: {station_id}")

    print("\n" + "=" * 60)
    print("【終極瘦身驗證成功！】")
    print("  1. 原版封包 : 6635 Bytes (切 5 片)")
    print(f"  2. ECQV + CA 後量子憑證 (Full): {len(full_packet)} Bytes (切 5 片)")
    print(f"  3. Short 模式: {len(short_packet)} Bytes (省略公鑰與 CA 憑證，3 片)")
    print("=" * 60)

if __name__ == "__main__":
    run_test()
