import time, random, json
from OBU.gen_payload import format_temporary_id

def generate_ssm_payload(obu_id, intersection_id=1, approach_id=1, request_id=1, status=4, sim_time=None, sequence_number=1, prewarmed_rsus=None):
    """
    產生符合 SAE J2735 SEP2024 (Section 5.28) 的精簡號誌狀態訊息 (Signal Status Message, SSM, msgID=30)
    作為路口 RSU 回應緊急車輛 SRM 優先號誌請求之回條 (ACK)。
    只保留必要欄位 (Mandatory)，嚴格剔除所有非必要之 Optional 欄位以實現極簡傳輸負載 (~240 bytes)。
    
    參數:
      - obu_id: 請求車輛識別碼 (例如: "AMB-217")
      - intersection_id: 目標路口編號 (預設: 1)
      - approach_id: 進口道編號 (預設: 1)
      - request_id: 請求識別流水號 (預設: 1)
      - status: 優先權回應狀態 (4 = granted 放行/核准, 5 = rejected 拒絕, 6 = need_cert 需公鑰降級)
      - sim_time: 模擬時間注入 (Veins / OMNeT++)
      - sequence_number: 回填 Echo 車輛在 SRM 請求中所附帶的序號 (DE_MsgCount, 0..127)
      - prewarmed_rsus: 有線骨幹預熱完成之下游路口清單 (例如: [2, 3])
    """
    now = sim_time if sim_time is not None else time.time()
    dsecond = int((now % 60) * 1000)

    ssm_data = {
        "msgID": 30,             # SAE J2735 DE_DSRC_MessageID: signalStatusMessage = 30
        "second": dsecond,       # DE_DSecond (0..65535 ms)
        "sequenceNumber": random.randint(0, 127), # DE_MsgCount (0..127)
        "status": [              # DF_SignalStatusList
            {
                "sequenceNumber": 1,
                "id": {"id": intersection_id}, # DF_IntersectionReferenceID (省略可選 region)
                "sigStatus": [    # DF_SignalStatusPackageList
                    {
                        "requester": {  # DF_SignalRequesterInfo
                            "id": {"entityID": format_temporary_id(obu_id)}, # DF_VehicleID: DE_TemporaryID (SIZE(4))
                            "request": request_id,      # DE_RequestID
                            "sequenceNumber": sequence_number,  # DE_MsgCount (回填 Echo 車輛之 SRM 序號)
                            "role": 14                  # DE_BasicVehicleRole: 14=ambulance
                        },
                        "inboundOn": {"approach": approach_id}, # DF_IntersectionAccessPoint
                        "status": status                # DE_PrioritizationResponseStatus: 4=granted, 6=need_cert
                    }
                ]
            }
        ],
        "full_timestamp": now
    }
    if prewarmed_rsus:
        ssm_data["prewarmed_rsus"] = prewarmed_rsus
    return ssm_data

def extract_pure_j2735_message(payload_data):
    """
    剔除自訂外殼與延遲評測欄位 (msgID, full_timestamp, prewarmed_rsus)，
    還原為純粹符合 SAE J2735 標準定義之訊息本體 (如 SignalStatusMessage)。
    以確保能直接傳入嚴格之 ASN.1 UPER 編碼器。
    """
    return {k: v for k, v in payload_data.items() if k not in ("msgID", "full_timestamp", "prewarmed_rsus")}

def to_message_frame(payload_data):
    """
    將酬載封裝為符合 SAE J2735 Section 5.1 (Page 27) 之標準 MessageFrame：
    MessageFrame ::= SEQUENCE {
        messageId   DSRCmsgID, -- 例如: 30=signalStatusMessage
        value       ANY DEFINED BY messageId -- 純粹的 J2735 訊息結構
    }
    """
    msg_id = payload_data.get("msgID", 30)
    pure_val = extract_pure_j2735_message(payload_data)
    return {
        "messageId": msg_id,
        "value": pure_val
    }
