import time, random, json
from OBU.main import OBU_ID

def generate_bsm_payload(obu_id):
    """
    產生模擬的 SAE J2735 BSM 格式 Payload (JSON 版)
    """
    # 1. 座標產生 (範圍限制在台灣)
    # 緯度範圍: 21.9 ~ 25.3
    lat = round(random.uniform(22.60, 22.70), 7) # 鎖定在高雄中山大學附近
    # 經度範圍: 120.0 ~ 122.0
    lon = round(random.uniform(120.20, 120.30), 7)
    
    # 2. J2735 DSecond (毫秒計時器)
    # 標準規定：這是一個 0~60000 的整數，代表當前分鐘內的毫秒數
    # 用於短時間內的訊息同步與順序檢查
    dsecond = int((time.time() % 60) * 1000)
    
    # 3. 完整的 BSM 結構
    bsm_data = {
        "msgID": 20,                # 20 是 SAE J2735 中 BSM 的十進位代碼 (0x14)
        "stationID": obu_id,    # 車輛識別碼
        "bsecMark": dsecond,        # 時間戳記 (毫秒)
        "full_timestamp": time.time(), # 額外加入絕對時間戳記，方便 RSU 計算延遲
        "coreData": {
            "msgCnt": random.randint(0, 127), # 訊息序號 (0~127)
            "lat": lat,
            "long": lon,
            "elev": 15.5,           # 高度 (公尺)
            "accuracy": {           # 位置精確度
                "semiMajor": 2, 
                "semiMinor": 2
            },
            "transmission": "forward", # 檔位狀態
            "speed": round(random.uniform(0, 80), 2),   # 時速 (km/h)
            "heading": random.randint(0, 360),          # 航向角 (0-360度)
            "brakes": {             # 煞車狀態
                "wheelBrakes": "0000", 
                "abs": "unavailable"
            }
        }
    }
    
    return bsm_data

if __name__ == "__main__":
    # 測試產生
    payload = generate_bsm_payload(OBU_ID)
    with open(f'OBU/payload/{OBU_ID}_payload.json', 'w') as f:
        json.dump(payload, f, indent=2)
    print(f"已生成 BSM Payload")