"""
單一路口緊急車輛通行模擬 (Monte Carlo)

情境：一台 OBU 以固定速度從距離 RSU D 公尺處出發駛向單一路口，
依 OBU.main 的發送迴圈週期性送出 SRM，直到 RSU 觸發緊急綠燈 (SSM status=4) 或車輛抵達路口。
抵達時間 T_arr = D / v，抵達前未觸發綠燈即視為該趟次失敗。

模擬方式：
  - 封包產生、分片、RSU 重組/驗證/逾時/XOR 修復/黑名單全部呼叫專案原始程式碼 (真實密碼學運算)。
  - 只有「時鐘」與「無線通道」為模擬：RSU / OBU 讀到的 time.time() 為虛擬時鐘，
    運算耗時以固定常數 (預設為本機量測中位數，可用 --calibrate 重新量測) 推進虛擬時鐘，確保固定種子可重現。

─── 通道模型 (IEEE 802.11p / DSRC 10 MHz) ─────────────────────────────────────
  距離：     d(t)   = sqrt( max(D - v·t, 0)^2 + h^2 )            h = RSU 側向/桿高偏移 (--rsu-offset)
  位元錯誤率：BER(d) = min( BER_ref · (d / d_ref)^α , 0.5 )        BER_ref 依環境等級，α 為路徑衰減指數
  分片掉包率：PER(L, d) = 1 - (1 - BER(d))^(8·(L + H))            L = UDP payload，H = 64B 鏈路層開銷
              (MAC 24 + LLC/SNAP 8 + IPv4 20 + UDP 8 + FCS 4)
  空中延遲：  T(L) = AIFS + U{0..CW}·slot + T_preamble + 8·(L + H) / R + Exp(μ_env) + d / c
              AIFS = SIFS + AIFSN·slot = 32 + 2·13 = 58 µs (AC_VO)，CW = 3，slot = 13 µs，
              T_preamble = 40 µs，R = 資料率 (--rate-mbps)，μ_env = 環境壅塞排隊平均延遲
  同一則訊息的分片背靠背送出：第 i+1 片在第 i 片傳完後才開始佔用通道。

─── 掉包模型 ──────────────────────────────────────────────────────────────────
  獨立 (iid)：每個分片依 PER(L, d) 獨立掉包。
  突發 (ge)：Gilbert-Elliott 兩狀態連續時間馬可夫鏈 (好 G / 壞 B，例如遮蔽或深度衰落)。
    - 狀態平均停留時間 T_G、T_B (--ge-good-ms / --ge-bad-ms)，
      轉移率 λ = 1/T_G (G→B)、μ = 1/T_B (B→G)，穩態 π_B = T_B / (T_G + T_B)。
    - 每個分片開始傳送時依經過時間 Δt 抽樣狀態：
        P(壞 | Δt) = π_B + (P_0 - π_B) · e^{-(λ+μ)Δt}，P_0 = 上次狀態為壞 ? 1 : 0
    - 壞狀態 BER 為好狀態的 β 倍 (--ge-beta)：BER_B = min(β · BER_G, 0.5)。
    - BER_G 以二分法求解，使長期平均掉包率與獨立模型相同 (以 MTU 分片 L_ref = 1400B 為基準)：
        π_G · PER(L_ref, BER_G) + π_B · PER(L_ref, BER_B) = PER(L_ref, BER(d))
      → 兩種模型平均掉包率一致，差異只在「掉包是否成串集中」，可公平比較冗餘策略抗突發能力。
      (若改為匹配平均 BER，錯誤集中會使平均掉包率大幅下降，突發模型反而顯得較輕鬆。)

─── 閃黃燈與黃燈緩衝 ──────────────────────────────────────────────────────────
  閃黃燈：某則訊息的 F1 通過 ECC 驗證並被 RSU 接受 (成功與失敗趟次皆記錄)。
  黃燈緩衝：某則訊息已閃黃燈，但該則訊息最終未觸發綠燈 (後續分片掉包/逾時/驗證失敗)，
            OBU 需在下一週期重送；成功趟次中發生在綠燈之前的緩衝另外統計。

─── 輸出 (--out 目錄，欄位名稱為繁體中文，內容值為英文代碼) ───────────────────
  summary.csv               每組實驗的彙總指標
  trials.csv                每趟次原始紀錄
  cdf_time_to_green.csv     觸發綠燈耗時 CDF (分母為全部趟次，曲線上限即成功率)
  attempts_distribution.csv 觸發成功前嘗試次數分布
  channel_profile.csv       各環境下 BER / PER / 空中延遲隨距離與分片大小的變化
  params.json               本次實驗完整參數 (指令、git commit、通道/運算耗時設定)，供重現
  未指定 --out 時，自動輸出至 sim/results/ 底下下一個未使用的編號資料夾 (1, 2, 3...)。

用法 (於專案根目錄)：
  python3 -m sim.trip_sim --distance 300 --speed 60 --interval 1.0
"""
import argparse, contextlib, csv, io, json, math, os, random, statistics, sys
import time as _real_time
from concurrent.futures import ProcessPoolExecutor

ENV_LEVELS    = ("none", "low", "mid", "high")
LOSS_MODELS   = ("iid", "ge")
PACKET_TYPES  = ("full", "short")
MODES         = ("none", "dup", "xor")

OBU_ID    = "AMB-217"
OBU_ADDR  = ("10.0.0.2", 40000)
RSU_ID    = 1
SIM_EPOCH = 1_800_000_000.0   # 虛擬時鐘起點 (Unix 秒)，每趟次重新從此開始

# ─── 802.11p 鏈路參數 ───────────────────────────────────────────────────────
LINK_OVERHEAD = 64        # MAC 24 + LLC/SNAP 8 + IPv4 20 + UDP 8 + FCS 4 (bytes)
SLOT          = 13e-6
SIFS          = 32e-6
AIFSN         = 2
CW_MIN        = 3
T_PREAMBLE    = 40e-6
LIGHT_SPEED   = 3e8
GE_REF_SIZE   = 1400      # 突發模型匹配平均掉包率的基準分片大小 (MTU 分片)

# 各環境等級：d_ref 處的 BER 與通道壅塞平均排隊延遲 (ms)
DEFAULT_BER_REF  = {"none": 0.0, "low": 1e-6, "mid": 5e-6, "high": 2e-5}
DEFAULT_QUEUE_MS = {"none": 0.0, "low": 0.2,  "mid": 0.5,  "high": 1.0}

# 運算耗時常數 (ms)：本機量測中位數，--calibrate 可重新量測
DEFAULT_COSTS_MS = {
    "obu_gen"   : 1.2,   # OBU gen_packet (ECDSA + ML-DSA-44 簽章)
    "f1_verify" : 1.9,   # RSU verify_f1_ecc (快取命中時)
    "ecqv"      : 1.8,   # RSU ECQV 公鑰重構 Q_U = e·P_U + Q_CA (快取未命中時額外耗時)
    "full_verify": 2.0,  # RSU parse_packet (ML-DSA-44 + ECC 雙簽驗證，快取命中時)
}

# ─── CSV 中文欄位 (檔名與內容值維持英文代碼) ────────────────────────────────
CONFIG_HEADERS = {"env": "掉包環境", "channel": "掉包模型", "packet": "封包類型", "mode": "模式"}

SUMMARY_HEADERS = {
    **CONFIG_HEADERS,
    "trials"             : "趟次數",
    "seed"               : "亂數種子",
    "distance_m"         : "出發距離(m)",
    "speed_kmh"          : "車速(km/h)",
    "interval_s"         : "發送間隔(s)",
    "arrival_time_s"     : "抵達路口時間(s)",
    "msg_bytes"          : "單則訊息大小(B)",
    "frags_per_msg"      : "單則分片數",
    "udp_bytes_per_msg"  : "單則傳輸量(B)",
    "success_rate_pct"   : "綠燈觸發成功率(%)",
    "first_try_rate_pct" : "一次成功率(%)",
    "fail_no_flash"      : "失敗趟次_未曾閃黃燈",
    "fail_flash_no_green": "失敗趟次_有閃黃燈但未綠燈",
    "ttg_mean_s"         : "觸發耗時_平均(s)",
    "ttg_p50_s"          : "觸發耗時_中位數(s)",
    "ttg_p90_s"          : "觸發耗時_P90(s)",
    "ttg_p95_s"          : "觸發耗時_P95(s)",
    "ttg_max_s"          : "觸發耗時_最大(s)",
    "attempts_mean"      : "嘗試次數_平均",
    "attempts_p50"       : "嘗試次數_中位數",
    "attempts_p95"       : "嘗試次數_P95",
    "attempts_max"       : "嘗試次數_最大",
    "e2e_mean_ms"        : "綠燈SSM端到端延遲_平均(ms)",
    "e2e_p50_ms"         : "綠燈SSM端到端延遲_中位數(ms)",
    "e2e_p95_ms"         : "綠燈SSM端到端延遲_P95(ms)",
    "e2e_p99_ms"         : "綠燈SSM端到端延遲_P99(ms)",
    "e2e_max_ms"         : "綠燈SSM端到端延遲_最大(ms)",
    "flash_msg_rate_pct" : "閃黃燈觸發率_每則訊息(%)",
    "flash_any_pct"      : "閃黃燈至少一次比例_全部趟次(%)",
    "flash_any_ok_pct"   : "閃黃燈至少一次比例_成功趟次(%)",
    "flash_any_fail_pct" : "閃黃燈至少一次比例_失敗趟次(%)",
    "flash_mean_ms"      : "首次閃黃燈延遲_平均(ms)",
    "flash_p50_ms"       : "首次閃黃燈延遲_中位數(ms)",
    "flash_p95_ms"       : "首次閃黃燈延遲_P95(ms)",
    "buffer_before_green_pct": "綠燈前曾黃燈緩衝比例_成功趟次(%)",
    "buffer_count_mean"  : "綠燈前黃燈緩衝次數_平均",
    "buffer_count_max"   : "綠燈前黃燈緩衝次數_最大",
    "buffer_to_green_mean_s": "首次黃燈緩衝至綠燈耗時_平均(s)",
    "buffer_to_green_p50_s" : "首次黃燈緩衝至綠燈耗時_中位數(s)",
    "buffer_to_green_p95_s" : "首次黃燈緩衝至綠燈耗時_P95(s)",
    "bytes_up_mean"      : "每次綠燈上行傳輸量_平均(B)",
    "bytes_up_p50"       : "每次綠燈上行傳輸量_中位數(B)",
    "bytes_up_p95"       : "每次綠燈上行傳輸量_P95(B)",
    "bytes_up_max"       : "每次綠燈上行傳輸量_最大(B)",
    "bytes_down_mean"    : "每次綠燈下行SSM量_平均(B)",
}

TRIAL_HEADERS = {
    **CONFIG_HEADERS,
    "trial"           : "趟次",
    "success"         : "成功觸發綠燈(1/0)",
    "first_try"       : "一次成功(1/0)",
    "time_to_green_s" : "觸發耗時(s)",
    "attempts"        : "嘗試次數",
    "e2e_ms"          : "綠燈SSM端到端延遲(ms)",
    "flash_any"       : "有閃黃燈(1/0)",
    "flash_msgs"      : "閃黃燈訊息數",
    "first_flash_ms"  : "首次閃黃燈延遲(ms)",
    "buffer_count"    : "黃燈緩衝次數",
    "buffer_before_green": "綠燈前曾黃燈緩衝(1/0)",
    "buffer_to_green_s": "首次黃燈緩衝至綠燈耗時(s)",
    "bytes_up"        : "上行傳輸量(B)",
    "bytes_down"      : "下行傳輸量(B)",
    "green_distance_m": "觸發時距路口(m)",
}

CDF_HEADERS = {**CONFIG_HEADERS, "time_to_green_s": "觸發耗時(s)", "cdf": "累積機率"}

ATTEMPT_HEADERS = {
    **CONFIG_HEADERS,
    "attempts"      : "嘗試次數",
    "count"         : "趟次數",
    "pct_of_success": "佔成功趟次(%)",
    "pct_of_trials" : "佔全部趟次(%)",
}

PROFILE_HEADERS = {
    "env"               : "掉包環境",
    "distance_m"        : "距停止線(m)",
    "radio_distance_m"  : "無線距離(m)",
    "frag_udp_bytes"    : "分片大小(B)",
    "ber"               : "獨立模型BER",
    "per_pct"           : "獨立模型PER(%)",
    "ge_good_per_pct"   : "突發模型_好狀態PER(%)",
    "ge_bad_per_pct"    : "突發模型_壞狀態PER(%)",
    "ge_avg_per_pct"    : "突發模型_長期平均PER(%)",
    "airtime_mean_ms"   : "平均空中時間(ms)",
}


# ─── 通道 ──────────────────────────────────────────────────────────────────
class Channel:
    def __init__(self, env, model, args, rng):
        self.ber_ref = args.ber[env]
        self.queue_s = args.queue_ms[env] / 1000.0
        self.d_ref   = args.d_ref
        self.alpha   = args.alpha
        self.rate    = args.rate_mbps * 1e6
        self.rng     = rng

        # Gilbert-Elliott 突發參數 (見模組說明)
        self.ge      = model == "ge"
        t_g, t_b     = args.ge_good_ms / 1000.0, args.ge_bad_ms / 1000.0
        self.ge_rate = 1.0 / t_g + 1.0 / t_b             # λ + μ
        self.pi_bad  = t_b / (t_g + t_b)
        self.beta    = args.ge_beta
        self.bad, self.t_state = None, 0.0
        self._good_ber_cache = {}

    def reset(self):
        """每趟次開始時重設突發狀態 (首次抽樣依穩態機率)。"""
        self.bad, self.t_state = None, 0.0

    def _sample_state(self, t):
        if self.bad is None:
            p_bad = self.pi_bad
        else:
            p0    = 1.0 if self.bad else 0.0
            p_bad = self.pi_bad + (p0 - self.pi_bad) * math.exp(-self.ge_rate * max(t - self.t_state, 0.0))
        self.bad, self.t_state = self.rng.random() < p_bad, t
        return self.bad

    @staticmethod
    def _per_from_ber(ber, size):
        return 1.0 - (1.0 - ber) ** (8 * (size + LINK_OVERHEAD))

    def _good_ber(self, d):
        """二分法求 BER_G，使突發模型在 L_ref 的長期平均掉包率等於獨立模型 (距離以 0.1m 快取)。"""
        key = round(d, 1)
        if key not in self._good_ber_cache:
            ber    = self.ber(key)
            target = self._per_from_ber(ber, GE_REF_SIZE)
            avg    = lambda x: (1 - self.pi_bad) * self._per_from_ber(x, GE_REF_SIZE) \
                               + self.pi_bad * self._per_from_ber(min(self.beta * x, 0.5), GE_REF_SIZE)
            lo, hi = 0.0, ber
            for _ in range(50):
                mid = (lo + hi) / 2
                lo, hi = (mid, hi) if avg(mid) < target else (lo, mid)
            self._good_ber_cache[key] = (lo + hi) / 2
        return self._good_ber_cache[key]

    def ber(self, d, bad=None):
        """bad=None 為獨立模型 BER；True/False 為突發模型的壞/好狀態 BER。"""
        if bad is None:
            return min(self.ber_ref * (d / self.d_ref) ** self.alpha, 0.5)
        g = self._good_ber(d)
        return min(self.beta * g, 0.5) if bad else g

    def per(self, size, d, bad=None):
        return self._per_from_ber(self.ber(d, bad), size)

    def airtime(self, size):
        """單一分片佔用通道時間 (不含傳播延遲)，含隨機退避與壅塞排隊。"""
        backoff = self.rng.randint(0, CW_MIN) * SLOT
        queue   = self.rng.expovariate(1.0 / self.queue_s) if self.queue_s > 0 else 0.0
        return SIFS + AIFSN * SLOT + backoff + T_PREAMBLE + 8 * (size + LINK_OVERHEAD) / self.rate + queue

    def transmit(self, size, t_start, d):
        """回傳 (通道釋放時間, 是否送達, 抵達時間)。每次固定抽同樣數量的亂數以維持可重現性。"""
        bad   = self._sample_state(t_start) if self.ge else None
        t_end = t_start + self.airtime(size)
        ok    = self.rng.random() >= self.per(size, d, bad)
        return t_end, ok, t_end + d / LIGHT_SPEED


# ─── 虛擬時鐘：取代 RSU / OBU 模組內的 time 模組 ─────────────────────────────
class VirtualClock:
    def __init__(self):
        self.now = SIM_EPOCH

    def time(self):
        return self.now

    def __getattr__(self, name):   # strftime / localtime 等其餘函式沿用真實 time 模組
        return getattr(_real_time, name)


class CaptureSock:
    """攔截 RSU 下行的 SSM，記錄送出當下的虛擬時間。"""
    def __init__(self, clock):
        self.clock = clock
        self.sent  = []

    def sendto(self, data, addr):
        self.sent.append((self.clock.now, data))


# ─── Worker 狀態 (每個行程各一份) ───────────────────────────────────────────
_W = {}

def _init_worker(costs_ms):
    import RSU.main as rsu
    import RSU.parse as parse
    import RSU.gen_payload as rsu_gen
    import OBU.gen_payload as obu_gen
    from OBU.encode_packet import gen_packet
    from OBU.fragment import make_fragments
    from fec import make_fragments_xor

    clock = VirtualClock()
    for mod in (rsu, parse, rsu_gen, obu_gen):
        mod.time = clock

    costs = {k: v / 1000.0 for k, v in costs_ms.items()}
    state = {"f1_ok_time": None}

    # 以包裝函式在原始運算後推進虛擬時鐘 (RSU.main 透過 parse.xxx 呼叫，故替換模組屬性即可生效)
    orig_f1, orig_parse, orig_ecqv = parse.verify_f1_ecc, parse.parse_packet, parse.reconstruct_obu_pubkey

    def f1_wrapped(*a, **k):
        r = orig_f1(*a, **k)
        clock.now += costs["f1_verify"]
        if r[0]:
            state["f1_ok_time"] = clock.now
        return r

    def parse_wrapped(*a, **k):
        r = orig_parse(*a, **k)
        clock.now += costs["full_verify"]
        return r

    def ecqv_wrapped(*a, **k):
        clock.now += costs["ecqv"]
        return orig_ecqv(*a, **k)

    parse.verify_f1_ecc          = f1_wrapped
    parse.parse_packet           = parse_wrapped
    parse.reconstruct_obu_pubkey = ecqv_wrapped

    # 取得已驗證的金鑰資料，供 Short 實驗模擬「上游路口已透過有線骨幹預熱本路口」
    with contextlib.redirect_stdout(io.StringIO()):
        auth_pkt = gen_packet(OBU_ID, intersection_id=RSU_ID, known_RSU=False)
        assert orig_parse(auth_pkt, rsu_id=RSU_ID) is not None, "初始化 Full 封包驗證失敗，請先完成 CA/RSU/OBU setup"
    auth = dict(parse.LAST_VERIFIED_AUTH)

    _W.update(rsu=rsu, parse=parse, clock=clock, costs=costs, state=state, auth=auth,
              gen_packet=gen_packet, make_fragments=make_fragments, make_fragments_xor=make_fragments_xor)


def _reset_rsu():
    rsu, parse = _W["rsu"], _W["parse"]
    for d in (rsu.reassemble_buffer, rsu.recent_completed, rsu.id_active_session, rsu.id_session_meta,
              rsu.ip_rate_log, rsu.obu_f1_rate_log, rsu.blacklist):
        d.clear()
    parse.clear_all_caches()
    parse.LAST_VERIFIED_AUTH = {}
    parse.LAST_PARSE_STATUS  = "OK"


def _build_fragments(packet, msg_id, mode):
    """依 OBU.main 的三種冗餘策略回傳實際送出的 UDP 封包順序。"""
    if mode == "xor":
        data, parity = _W["make_fragments_xor"](packet, msg_id)
        return data + ([parity] if parity is not None else [])
    frags = _W["make_fragments"](packet, msg_id)
    return frags + [frags[0]] if mode == "dup" else frags


def _distance(args, t):
    return math.hypot(max(args.distance - args.speed_mps * t, 0.0), args.rsu_offset)


def _run_trial(args, packet_type, mode, ch):
    rsu, parse, clock, costs, state = _W["rsu"], _W["parse"], _W["clock"], _W["costs"], _W["state"]
    _reset_rsu()
    ch.reset()

    known = packet_type == "short"
    if known:
        a = _W["auth"]
        parse.inject_prewarm_cache(RSU_ID, a["obu_id_raw"], a["P_U_bytes"], a["vk"], a["pqc_pub"], expire_at=None)

    t_arr = args.distance / args.speed_mps
    sock  = CaptureSock(clock)
    t, msg_id = 0.0, 0
    rec = {"attempts": 0, "bytes_up": 0, "bytes_down": 0, "flash_msgs": 0, "buffer_count": 0,
           "first_flash_ms": None, "first_buffer_t": None, "green_t": None, "e2e_ms": None}

    while t < t_arr:
        msg_id += 1
        rec["attempts"] += 1
        msg_flash_t = None                 # 本則訊息閃黃燈的趟次內時間 (None = 未閃黃燈)
        clock.now = SIM_EPOCH + t          # SRM full_timestamp = 本則訊息開始產生的時間
        msg_ts = clock.now
        packet = _W["gen_packet"](OBU_ID, intersection_id=RSU_ID, known_RSU=known)
        frags  = _build_fragments(packet, msg_id, mode)

        # 上行：分片背靠背送出
        t_tx, arrivals = t + costs["obu_gen"], []
        for f in frags:
            t_end, ok, t_rx = ch.transmit(len(f), t_tx, _distance(args, t_tx))
            rec["bytes_up"] += len(f)
            if ok:
                arrivals.append((t_rx, f))
            t_tx = t_end
        t_send_end = t_tx

        # RSU：依抵達順序處理，忙碌時排隊
        busy, nack_t = 0.0, None
        for t_rx, f in arrivals:
            clock.now = SIM_EPOCH + max(t_rx, busy)
            rsu.prune_expired_sessions()
            state["f1_ok_time"] = None
            sock.sent.clear()
            rsu.process_fragment(f, OBU_ADDR, sock=sock, rsu_id=RSU_ID)
            busy = clock.now - SIM_EPOCH

            # 閃黃燈：F1 ECC 驗證通過且被 RSU 接受 (未被黑名單/限流/去重擋下)
            key = (msg_id, OBU_ADDR)
            accepted = (key in rsu.reassemble_buffer and rsu.reassemble_buffer[key]["fragments"][0] is not None) \
                       or key in rsu.recent_completed
            if state["f1_ok_time"] is not None and accepted and msg_flash_t is None:
                msg_flash_t = state["f1_ok_time"] - SIM_EPOCH
                rec["flash_msgs"] += 1
                if rec["first_flash_ms"] is None:
                    rec["first_flash_ms"] = (state["f1_ok_time"] - msg_ts) * 1000

            for t_ssm, data in sock.sent:
                rec["bytes_down"] += len(data)
                st = json.loads(data)["status"][0]["sigStatus"][0]["status"]
                if st == 4 and rec["green_t"] is None:
                    rec["green_t"] = t_ssm - SIM_EPOCH
                    rec["e2e_ms"]  = (t_ssm - msg_ts) * 1000
                elif st in (5, 6):
                    # 下行 NACK 也經過同一通道；送達才會讓 OBU 降級回 Full
                    t_rel = t_ssm - SIM_EPOCH
                    _, ok, t_rx_dl = ch.transmit(len(data), t_rel, _distance(args, t_rel))
                    if ok and nack_t is None:
                        nack_t = t_rx_dl
            if rec["green_t"] is not None:
                break

        if rec["green_t"] is not None:
            break
        # 黃燈緩衝：本則訊息已閃黃燈 (F1 通過) 但未能觸發綠燈 (後續分片掉包/逾時/驗證失敗)
        if msg_flash_t is not None:
            rec["buffer_count"] += 1
            if rec["first_buffer_t"] is None:
                rec["first_buffer_t"] = msg_flash_t
        if nack_t is not None:
            known = False

        # OBU.main：recvfrom 等待 SSM (ack_timeout)，之後 sleep(interval)
        wait_end = t_send_end + args.ack_timeout
        if nack_t is not None and nack_t < wait_end:
            wait_end = nack_t
        t = wait_end + args.interval

    green_t = rec["green_t"]
    success = green_t is not None and green_t <= t_arr
    return {
        "success"        : int(success),
        "first_try"      : int(success and rec["attempts"] == 1),
        "time_to_green_s": round(green_t, 6) if success else "",
        "attempts"       : rec["attempts"],
        "e2e_ms"         : round(rec["e2e_ms"], 4) if success else "",
        "flash_any"      : int(rec["flash_msgs"] > 0),
        "flash_msgs"     : rec["flash_msgs"],
        "first_flash_ms" : round(rec["first_flash_ms"], 4) if rec["first_flash_ms"] is not None else "",
        "buffer_count"   : rec["buffer_count"],
        "buffer_before_green": int(success and rec["buffer_count"] > 0),
        "buffer_to_green_s": round(green_t - rec["first_buffer_t"], 6)
                             if success and rec["first_buffer_t"] is not None else "",
        "bytes_up"       : rec["bytes_up"],
        "bytes_down"     : rec["bytes_down"],
        "green_distance_m": round(max(args.distance - args.speed_mps * green_t, 0.0), 2) if success else "",
    }


def _run_config(task):
    args, env, channel, packet_type, mode = task
    random.seed(args.seed)                     # gen_payload / gen_ssm 內部使用的全域 random
    ch = Channel(env, channel, args, random.Random(args.seed))
    rows = []
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        for i in range(args.trials):
            r = _run_trial(args, packet_type, mode, ch)
            rows.append({"env": env, "channel": channel, "packet": packet_type, "mode": mode, "trial": i + 1, **r})
            buf.seek(0); buf.truncate()        # RSU 會大量 print，逐趟次丟棄避免記憶體膨脹
    return rows


# ─── 量測運算耗時 ────────────────────────────────────────────────────────────
def calibrate(n=30):
    import RSU.parse as parse
    from OBU.encode_packet import gen_packet
    from OBU.fragment import make_fragments

    def med(fn):
        ts = []
        for _ in range(n):
            t0 = _real_time.perf_counter(); fn(); ts.append(_real_time.perf_counter() - t0)
        return statistics.median(ts) * 1000

    with contextlib.redirect_stdout(io.StringIO()):
        pkt = gen_packet(OBU_ID, intersection_id=RSU_ID, known_RSU=False)
        f1  = make_fragments(pkt, 1)[0][4:]
        gen  = med(lambda: gen_packet(OBU_ID, intersection_id=RSU_ID, known_RSU=False))
        parse.verify_f1_ecc(f1, rsu_id=RSU_ID)
        f1_hot = med(lambda: parse.verify_f1_ecc(f1, rsu_id=RSU_ID))
        def f1_cold():
            parse.clear_all_caches(); parse.verify_f1_ecc(f1, rsu_id=RSU_ID)
        cold = med(f1_cold)
        parse.parse_packet(pkt, rsu_id=RSU_ID)
        full_hot = med(lambda: parse.parse_packet(pkt, rsu_id=RSU_ID))
    return {"obu_gen": gen, "f1_verify": f1_hot, "ecqv": max(cold - f1_hot, 0.0), "full_verify": full_hot}


# ─── 統計與輸出 ─────────────────────────────────────────────────────────────
def _pct(values, p):
    if not values:
        return ""
    s = sorted(values)
    k = (len(s) - 1) * p / 100
    lo, hi = math.floor(k), math.ceil(k)
    return round(s[lo] + (s[hi] - s[lo]) * (k - lo), 4)


def _mean(values):
    return round(statistics.fmean(values), 4) if values else ""


def _summarize(args, cfg, rows, sample):
    ok       = [r for r in rows if r["success"]]
    ttg      = [r["time_to_green_s"] for r in ok]
    att      = [r["attempts"] for r in ok]
    e2e      = [r["e2e_ms"] for r in ok]
    flash    = [r["first_flash_ms"] for r in rows if r["first_flash_ms"] != ""]
    up       = [r["bytes_up"] for r in ok]
    down     = [r["bytes_down"] for r in ok]
    fail     = [r for r in rows if not r["success"]]
    buf_ok   = [r for r in ok if r["buffer_before_green"]]
    b2g      = [r["buffer_to_green_s"] for r in buf_ok]
    n        = len(rows)
    no_flash = sum(1 for r in fail if not r["flash_any"])
    ratio    = lambda part, whole: round(100 * part / whole, 2) if whole else ""
    return {
        **cfg, "trials": n, "seed": args.seed,
        "distance_m": args.distance, "speed_kmh": args.speed, "interval_s": args.interval,
        "arrival_time_s": round(args.distance / args.speed_mps, 4),
        "msg_bytes": sample["msg_bytes"], "frags_per_msg": sample["frags"], "udp_bytes_per_msg": sample["udp_bytes"],
        "success_rate_pct": round(100 * len(ok) / n, 2),
        "first_try_rate_pct": round(100 * sum(r["first_try"] for r in rows) / n, 2),
        "fail_no_flash": no_flash, "fail_flash_no_green": n - len(ok) - no_flash,
        "ttg_mean_s": _mean(ttg), "ttg_p50_s": _pct(ttg, 50), "ttg_p90_s": _pct(ttg, 90),
        "ttg_p95_s": _pct(ttg, 95), "ttg_max_s": max(ttg) if ttg else "",
        "attempts_mean": _mean(att), "attempts_p50": _pct(att, 50), "attempts_p95": _pct(att, 95),
        "attempts_max": max(att) if att else "",
        "e2e_mean_ms": _mean(e2e), "e2e_p50_ms": _pct(e2e, 50), "e2e_p95_ms": _pct(e2e, 95),
        "e2e_p99_ms": _pct(e2e, 99), "e2e_max_ms": max(e2e) if e2e else "",
        # 閃黃燈：涵蓋所有趟次 (成功與失敗)；觸發率以「每則送出訊息」為分母
        "flash_msg_rate_pct": ratio(sum(r["flash_msgs"] for r in rows), sum(r["attempts"] for r in rows)),
        "flash_any_pct": ratio(sum(r["flash_any"] for r in rows), n),
        "flash_any_ok_pct": ratio(sum(r["flash_any"] for r in ok), len(ok)),
        "flash_any_fail_pct": ratio(sum(r["flash_any"] for r in fail), len(fail)),
        "flash_mean_ms": _mean(flash), "flash_p50_ms": _pct(flash, 50), "flash_p95_ms": _pct(flash, 95),
        # 黃燈緩衝：已閃黃燈但該則訊息未觸發綠燈；此處統計成功趟次在綠燈前的緩衝
        "buffer_before_green_pct": ratio(len(buf_ok), len(ok)),
        "buffer_count_mean": _mean([r["buffer_count"] for r in ok]),
        "buffer_count_max": max((r["buffer_count"] for r in ok), default=""),
        "buffer_to_green_mean_s": _mean(b2g), "buffer_to_green_p50_s": _pct(b2g, 50),
        "buffer_to_green_p95_s": _pct(b2g, 95),
        "bytes_up_mean": _mean(up), "bytes_up_p50": _pct(up, 50), "bytes_up_p95": _pct(up, 95),
        "bytes_up_max": max(up) if up else "", "bytes_down_mean": _mean(down),
    }


def _write_csv(path, rows, headers):
    """以中文欄位名稱輸出，內容值維持英文代碼。"""
    with open(path, "w", newline="", encoding="utf-8-sig") as f:   # utf-8-sig：Excel 開啟不亂碼
        w = csv.writer(f)
        w.writerow(headers.values())
        for r in rows:
            w.writerow(r[k] for k in headers)


def _message_samples():
    """各 packet/mode 組合的單則訊息大小與分片尺寸 (供彙總指標與通道特性)。"""
    from OBU.encode_packet import gen_packet
    from OBU.fragment import make_fragments
    from fec import make_fragments_xor
    import OBU.gen_payload as obu_gen
    out = {}
    # SRM 的 second / full_timestamp / sequenceNumber 會影響 JSON 長度：
    # 改用虛擬時鐘與固定種子取樣，使單則訊息大小每次執行都相同
    real_time, obu_gen.time = obu_gen.time, VirtualClock()
    rng_state = random.getstate()
    random.seed(0)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            for p in PACKET_TYPES:
                pkt = gen_packet(OBU_ID, intersection_id=RSU_ID, known_RSU=(p == "short"))
                for m in MODES:
                    if m == "xor":
                        data, parity = make_fragments_xor(pkt, 1)
                        frags = data + [parity]
                    else:
                        frags = make_fragments(pkt, 1)
                        frags = frags + [frags[0]] if m == "dup" else frags
                    out[(p, m)] = {"msg_bytes": len(pkt), "frags": len(frags),
                                   "udp_bytes": sum(len(f) for f in frags), "sizes": [len(f) for f in frags]}
    finally:
        obu_gen.time = real_time
        random.setstate(rng_state)
    return out


def _channel_profile(args, samples, envs):
    sizes = sorted({s for v in samples.values() for s in v["sizes"]})
    rows  = []
    step  = max(args.distance / 12, 1.0)
    dists = [round(i * step, 2) for i in range(int(args.distance / step) + 1)]
    for env in envs:
        ch = Channel(env, "ge", args, random.Random(0))
        for x in dists:
            d = math.hypot(x, args.rsu_offset)
            for L in sizes:
                tx = 8 * (L + LINK_OVERHEAD) / ch.rate
                mean_air = SIFS + AIFSN * SLOT + CW_MIN / 2 * SLOT + T_PREAMBLE + tx + ch.queue_s
                per_g, per_b = ch.per(L, d, False), ch.per(L, d, True)
                rows.append({"env": env, "distance_m": x, "radio_distance_m": round(d, 2),
                             "frag_udp_bytes": L, "ber": f"{ch.ber(d):.3e}",
                             "per_pct": round(100 * ch.per(L, d), 4),
                             "ge_good_per_pct": round(100 * per_g, 4),
                             "ge_bad_per_pct": round(100 * per_b, 4),
                             "ge_avg_per_pct": round(100 * ((1 - ch.pi_bad) * per_g + ch.pi_bad * per_b), 4),
                             "airtime_mean_ms": round(mean_air * 1000, 4)})
    return rows


def _next_run_dir(base="sim/results"):
    """回傳 base 底下下一個未使用的編號資料夾 (現有最大編號 + 1，從 1 開始)。"""
    used = [int(n) for n in os.listdir(base) if n.isdigit()] if os.path.isdir(base) else []
    return os.path.join(base, str(max(used, default=0) + 1))


def _git_commit():
    try:
        import subprocess
        # --dirty：工作區有未 commit 的修改時加上 -dirty 標記，避免誤以為結果對應該 commit 的程式碼
        return subprocess.run(["git", "describe", "--always", "--dirty"], capture_output=True, text=True).stdout.strip()
    except Exception:
        return ""


def _write_params(args, costs_ms, argv, elapsed_s=None):
    """將本次實驗參數 (含預設值與實際生效的 BER / 延遲 / 運算耗時) 存成 params.json，供日後重現。"""
    params = {
        "command"    : " ".join(["python3 -m sim.trip_sim", *argv]),
        "git_commit" : _git_commit(),
        "run_at"     : _real_time.strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed_s"  : round(elapsed_s, 1) if elapsed_s is not None else None,
        **{k: v for k, v in vars(args).items() if k not in ("ber", "queue_ms", "costs_ms", "calibrate")},
        "calibrated" : args.calibrate,
        "ber_ref"    : args.ber,
        "queue_ms"   : args.queue_ms,
        "costs_ms"   : {k: round(v, 4) for k, v in costs_ms.items()},
        "constants"  : {"link_overhead_bytes": LINK_OVERHEAD, "slot_us": SLOT * 1e6, "sifs_us": SIFS * 1e6,
                        "aifsn": AIFSN, "cw_min": CW_MIN, "preamble_us": T_PREAMBLE * 1e6,
                        "ge_ref_size_bytes": GE_REF_SIZE, "obu_id": OBU_ID, "rsu_id": RSU_ID},
    }
    with open(os.path.join(args.out, "params.json"), "w", encoding="utf-8") as f:
        json.dump(params, f, ensure_ascii=False, indent=2)


def _kv_floats(s, defaults):
    out = dict(defaults)
    if s:
        for item in s.split(","):
            k, v = item.split("=")
            out[k.strip()] = float(v)
    return out


def _build_parser():
    ap = argparse.ArgumentParser(description="單一路口緊急車輛通行 Monte Carlo 模擬")
    ap.add_argument("--distance",   type=float, default=300.0, help="OBU 出發點與 RSU (路口停止線) 距離，公尺 (預設 300)")
    ap.add_argument("--speed",      type=float, default=60.0,  help="OBU 固定車速，km/h (預設 60)")
    ap.add_argument("--interval",   type=float, default=1.0,
                    help="訊息發送間隔，秒；對應 OBU.main 的 frequency 參數 (每輪等待 SSM 後再 sleep 此秒數，預設 1.0)")
    ap.add_argument("--ack-timeout", type=float, default=0.3,  help="OBU 等待 SSM 回條逾時，秒 (同 OBU.main，預設 0.3)")
    ap.add_argument("--trials",     type=int,   default=1000,  help="每組實驗趟次 (預設 1000)")
    ap.add_argument("--seed",       type=int,   default=42,    help="固定亂數種子 (每組實驗皆使用此種子，預設 42)")
    ap.add_argument("--envs",       default=",".join(ENV_LEVELS),   help="掉包環境 (逗號分隔)：none,low,mid,high")
    ap.add_argument("--channels",   default=",".join(LOSS_MODELS),  help="掉包模型：iid (獨立),ge (Gilbert-Elliott 突發)")
    ap.add_argument("--packets",    default=",".join(PACKET_TYPES), help="封包類型：full,short")
    ap.add_argument("--modes",      default=",".join(MODES),        help="冗餘模式：none,dup,xor")
    ap.add_argument("--rate-mbps",  type=float, default=6.0,   help="802.11p 資料率 Mbps (預設 6)")
    ap.add_argument("--d-ref",      type=float, default=100.0, help="BER 參考距離 d_ref，公尺 (預設 100)")
    ap.add_argument("--alpha",      type=float, default=2.0,   help="BER 隨距離成長指數 α (預設 2)")
    ap.add_argument("--rsu-offset", type=float, default=10.0,  help="RSU 側向/桿高偏移 h，公尺 (預設 10)")
    ap.add_argument("--ber",        default="", help="覆寫 d_ref 處 BER，例如 low=1e-6,mid=5e-6,high=2e-5")
    ap.add_argument("--queue-ms",   default="", help="覆寫通道壅塞平均排隊延遲 ms，例如 low=0.2,mid=0.5,high=1")
    ap.add_argument("--ge-good-ms", type=float, default=200.0, help="突發模型：好狀態平均停留時間 ms (預設 200)")
    ap.add_argument("--ge-bad-ms",  type=float, default=20.0,  help="突發模型：壞狀態平均停留時間 ms (預設 20)")
    ap.add_argument("--ge-beta",    type=float, default=100.0, help="突發模型：壞/好狀態 BER 倍率 β (預設 100)")
    ap.add_argument("--costs-ms",   default="", help="覆寫運算耗時 ms，鍵：obu_gen,f1_verify,ecqv,full_verify")
    ap.add_argument("--calibrate",  action="store_true", help="以本機實測中位數取代預設運算耗時 (結果會隨機器變動)")
    ap.add_argument("--jobs",       type=int, default=os.cpu_count() or 1, help="平行行程數 (預設 CPU 核心數)")
    ap.add_argument("--out",        default=None,
                    help="CSV 輸出目錄 (預設為 sim/results/ 底下下一個未使用的編號資料夾，如 sim/results/2)")
    return ap


def _resolve_args(argv):
    """解析命令列並補齊衍生參數，回傳 (args, costs_ms)。"""
    args = _build_parser().parse_args(argv)
    if args.out is None:
        args.out = _next_run_dir()
    args.speed_mps = args.speed / 3.6
    args.ber       = _kv_floats(args.ber, DEFAULT_BER_REF)
    args.queue_ms  = _kv_floats(args.queue_ms, DEFAULT_QUEUE_MS)
    costs_ms       = calibrate() if args.calibrate else dict(DEFAULT_COSTS_MS)
    costs_ms       = _kv_floats(args.costs_ms, costs_ms)
    return args, costs_ms


def main():
    args, costs_ms = _resolve_args(sys.argv[1:])
    envs, channels, packets, modes = (s.split(",") for s in (args.envs, args.channels, args.packets, args.modes))

    os.makedirs(args.out, exist_ok=True)
    samples = _message_samples()
    tasks   = [(args, e, c, p, m) for e in envs for c in channels for p in packets for m in modes]

    print(f"抵達時間 T_arr = {args.distance / args.speed_mps:.2f}s，{len(tasks)} 組實驗 × {args.trials} 趟次，"
          f"運算耗時 (ms) = { {k: round(v, 3) for k, v in costs_ms.items()} }")
    t0 = _real_time.perf_counter()
    results = {}
    with ProcessPoolExecutor(max_workers=args.jobs, initializer=_init_worker, initargs=(costs_ms,)) as ex:
        for task, rows in zip(tasks, ex.map(_run_config, tasks)):
            results[task[1:]] = rows
            ok    = sum(r["success"] for r in rows)
            first = sum(r["first_try"] for r in rows)
            label = " / ".join(task[1:])
            print(f"  {label:<24} 成功率 {100 * ok / len(rows):6.2f}%  一次成功率 {100 * first / len(rows):6.2f}%")

    summary, trials, cdf, attempts = [], [], [], []
    for (env, c, p, m), rows in results.items():
        cfg = {"env": env, "channel": c, "packet": p, "mode": m}
        summary.append(_summarize(args, cfg, rows, samples[(p, m)]))
        trials.extend(rows)
        ttg = sorted(r["time_to_green_s"] for r in rows if r["success"])
        for i, v in enumerate(ttg, 1):
            cdf.append({**cfg, "time_to_green_s": v, "cdf": round(i / len(rows), 6)})
        att = [r["attempts"] for r in rows if r["success"]]
        for k in sorted(set(att)):
            cnt = att.count(k)
            attempts.append({**cfg, "attempts": k, "count": cnt,
                             "pct_of_success": round(100 * cnt / len(att), 3), "pct_of_trials": round(100 * cnt / len(rows), 3)})

    _write_csv(os.path.join(args.out, "summary.csv"), summary, SUMMARY_HEADERS)
    _write_csv(os.path.join(args.out, "trials.csv"), trials, TRIAL_HEADERS)
    _write_csv(os.path.join(args.out, "cdf_time_to_green.csv"), cdf, CDF_HEADERS)
    _write_csv(os.path.join(args.out, "attempts_distribution.csv"), attempts, ATTEMPT_HEADERS)
    _write_csv(os.path.join(args.out, "channel_profile.csv"), _channel_profile(args, samples, envs), PROFILE_HEADERS)
    elapsed = _real_time.perf_counter() - t0
    _write_params(args, costs_ms, sys.argv[1:], elapsed)
    print(f"完成 ({elapsed:.1f}s)，CSV 與 params.json 已輸出至 {args.out}/")


if __name__ == "__main__":
    main()
