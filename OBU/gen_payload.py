import time, random, json, hashlib

def format_temporary_id(obu_id):
    """
    依據 SAE J2735 Section 7.204 DE_TemporaryID (Page 208)：
    TemporaryID ::= OCTET STRING (SIZE(4))
    強制確保為剛好 4 個 Octets (4 bytes / 4-character ASCII)。
    避免 ASN.1 編碼器因長度不符 SIZE(4) 拋出異常。
    """
    if isinstance(obu_id, bytes):
        if len(obu_id) == 4:
            return obu_id.decode('latin-1')
        obu_id = obu_id.decode('utf-8', errors='ignore')

    s = str(obu_id)
    if len(s) == 4:
        return s

    # 移除非英數字元 (例如 "AMB-217" -> "AMB217" -> "AMB2")
    alnum = ''.join(c for c in s if c.isalnum())
    if len(alnum) >= 4:
        return alnum[:4]
    elif len(alnum) > 0:
        return alnum.ljust(4, '0')
    else:
        return hashlib.sha256(s.encode('utf-8')).hexdigest()[:4]

def generate_srm_payload(obu_id, intersection_id=1, approach_id=1, speed_kmh=60.0, heading_deg=90.0, lat=22.628012, lon=120.295217, sim_time=None):
    """
    產生符合 SAE J2735 SEP2024 (Section 5.27) 的精簡信號請求訊息 (Signal Request Message, SRM, msgID=29)
    只保留必要欄位 (Mandatory)，嚴格剔除所有非必要之 Optional 欄位 (如公車排班、乘客量、高度、區域擴展)
    以實現最小化傳輸負載與最高傳輸效率。

    參數 sim_time 支援 Veins / SUMO / OMNeT++ 虛擬模擬時鐘注入，避免與現實時間脫鉤。
    """
    now = sim_time if sim_time is not None else time.time()
    dsecond = int((now % 60) * 1000) # DE_DSecond (0..59999 ms)

    # 經緯度轉換為 J2735 標準 1/10 microdegree 整數
    lat_int = int(lat * 1e7)
    lon_int = int(lon * 1e7)

    # 速度轉換為 J2735 Velocity (單位: 0.02 m/s, 0..8190，8191 為無效/Unavailable 保留值)
    speed_mps = speed_kmh / 3.6
    speed_raw = min(8190, int(speed_mps / 0.02))

    # 航向角轉換為 J2735 Angle (0..28800, 單位: 0.0125 度)
    heading_raw = int((heading_deg % 360) / 0.0125)

    srm_data = {
        "msgID": 29,             # SAE J2735 外部識別碼: signalRequestMessage = 29
        "second": dsecond,       # DE_DSecond (0..65535)
        "sequenceNumber": random.randint(0, 127), # DE_MsgCount (0..127)
        "requests": [            # DF_SignalRequestList (僅包含當前目標路口之單一請求)
            {
                "request": {     # DF_SignalRequest
                    "id": {"id": intersection_id}, # DF_IntersectionReferenceID (省略可選 region)
                    "requestID": 1,                # DE_RequestID (0..255)
                    "requestType": 1,              # DE_PriorityRequestType: 1=priorityRequest
                    "inBoundLane": {"approach": approach_id} # DF_IntersectionAccessPoint (進口道號碼)
                }
            }
        ],
        "requestor": {           # DF_RequestorDescription
            "id": {"entityID": format_temporary_id(obu_id)}, # DF_VehicleID: DE_TemporaryID (SIZE(4))
            "type": {            # DF_RequestorType
                "role": 14,      # DE_BasicVehicleRole: 14=ambulance (救護車)
                "request": 14    # DE_RequestImportanceLevel: 14=最高優先權等級
            },
            "position": {        # DF_RequestorPositionVector
                "position": {    # DF_Position3D (省略可選 elevation 與 regional)
                    "lat": lat_int,
                    "long": lon_int
                },
                "speed": {       # DF_TransmissionAndSpeed (SAE J2735 Section 6.159 官方原生拼法為 transmisson)
                    "speed": speed_raw,
                    "transmisson": 2 # 2=forwardGears
                },
                "heading": heading_raw # DE_Angle
            }
        },
        "full_timestamp": now    # 供系統評估端到端總延遲 (非標準欄位，編碼至 ASN.1 前可剔除)
    }
    return srm_data

def extract_pure_j2735_message(payload_data):
    """
    剔除自訂外殼與延遲評測欄位 (msgID, full_timestamp)，
    還原為純粹符合 SAE J2735 標準定義之訊息本體 (如 SignalRequestMessage)。
    以確保能直接傳入嚴格之 ASN.1 UPER 編碼器。
    """
    return {k: v for k, v in payload_data.items() if k not in ("msgID", "full_timestamp")}

def to_message_frame(payload_data):
    """
    將酬載封裝為符合 SAE J2735 Section 5.1 (Page 27) 之標準 MessageFrame：
    MessageFrame ::= SEQUENCE {
        messageId   DSRCmsgID, -- 例如: 29=signalRequestMessage, 30=signalStatusMessage
        value       ANY DEFINED BY messageId -- 純粹的 J2735 訊息結構
    }
    """
    msg_id = payload_data.get("msgID", 29)
    pure_val = extract_pure_j2735_message(payload_data)
    return {
        "messageId": msg_id,
        "value": pure_val
    }

def generate_bsm_payload(obu_id):
    """
    (保留相容) 產生模擬的 SAE J2735 BSM 格式 Payload (JSON 版)
    """
    lat = round(random.uniform(22.60, 22.70), 7)
    lon = round(random.uniform(120.20, 120.30), 7)
    dsecond = int((time.time() % 60) * 1000)

    bsm_data = {
        "msgID": 20,
        "stationID": obu_id,
        "bsecMark": dsecond,
        "full_timestamp": time.time(),
        "coreData": {
            "msgCnt": random.randint(0, 127),
            "lat": lat,
            "long": lon,
            "elev": 15.5,
            "accuracy": {"semiMajor": 2, "semiMinor": 2},
            "transmission": "forward",
            "speed": round(random.uniform(0, 80), 2),
            "heading": random.randint(0, 360),
            "brakes": {"wheelBrakes": "0000", "abs": "unavailable"}
        }
    }
    return bsm_data