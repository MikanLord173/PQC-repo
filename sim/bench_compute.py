"""
系統運算耗時量測 (微基準測試)

逐項呼叫專案原始程式碼，每項量測 N 次 (預設 1000)，記錄每次耗時 (ms)。
  - 需要通過 150ms 時效檢查的項目，每次量測前 (不計時) 重新產生新鮮封包。
  - 「冷快取」項目每次量測前清空 RSU 快取；「熱快取」項目預先寫入快取。
  - 量測期間暫停垃圾回收 (同 timeit 慣例)，並先執行暖機次數排除首次載入成本。
  - 小於數微秒的運算 (如記憶體拷貝) 每個樣本內部重複多次再取平均，降低計時器本身開銷的影響。

分類：
  requested  使用者指定量測的功能 (編號 1~11)
  overlooked 流程中容易被忽略、但實際會發生的耗時 (磁碟 I/O、JSON、物件建構、SSM、預熱、端到端合計等)
  reference  不在系統流程中的對照組 (例如改用 OpenSSL 實作的 ECDSA)
  量測期間標準輸出導向 /dev/null，RSU/OBU 的 print 主控台輸出成本不計入。

輸出 (--out，預設 sim/results/ 底下下一個未使用的編號資料夾)：
  compute_summary.csv  各項統計 (平均/標準差/最小/中位數/P95/P99/最大)
  compute_samples.csv  每次量測的原始耗時
  params.json          量測參數與執行環境 (Python / liboqs / ecdsa 版本、CPU、git commit)

用法 (於專案根目錄)：
  python3 -m sim.bench_compute --iterations 1000
"""
import argparse, contextlib, csv, gc, hashlib, io, json, os, platform, struct, sys, time
from ctypes import create_string_buffer

import pki
from sim.trip_sim import _next_run_dir, _git_commit

OBU_ID   = "AMB-217"
RSU_ID   = 1
OBU_ADDR = ("10.0.0.2", 40000)

SUMMARY_HEADERS = {
    "group": "功能編號", "code": "項目代碼", "desc": "項目說明", "category": "分類",
    "n": "次數", "inner": "每樣本內部重複次數",
    "mean": "平均(ms)", "std": "標準差(ms)", "min": "最小(ms)", "p50": "中位數(ms)",
    "p95": "P95(ms)", "p99": "P99(ms)", "max": "最大(ms)",
}
SAMPLE_HEADERS = {"group": "功能編號", "code": "項目代碼", "iteration": "樣本序號", "ms": "耗時(ms)"}


class NullSock:
    """RSU 下行 SSM 的替身，只記錄送出內容。"""
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append(data)


def measure(n, op, prepare=None, warmup=20, inner=1):
    """
    每個樣本：prepare(i) (不計時) → 計時執行 op(*args) inner 次 → 取平均。
    回傳 n 個樣本的耗時 (ms)。
    """
    samples = []
    gc.disable()
    try:
        for i in range(n + warmup):
            args = prepare(i) if prepare else ()
            t0 = time.perf_counter_ns()
            for _ in range(inner):
                op(*args)
            t1 = time.perf_counter_ns()
            if i >= warmup:
                samples.append((t1 - t0) / 1e6 / inner)
    finally:
        gc.enable()
    return samples


def run(n):
    import oqs
    from ecdsa import NIST256p, SigningKey, VerifyingKey
    import ecdsa.ellipticcurve as ellipticcurve
    from cryptography.hazmat.primitives import serialization

    from CA.enroll import ca_process_enrollment
    from OBU.setup import generate_enrollment_request, obu_derive_key
    from OBU.encode_packet import gen_packet, load_cert
    from OBU.gen_payload import generate_srm_payload
    from OBU.fragment import make_fragments
    from fec import make_fragments_xor, recover_xor_heavy, _xor_layout
    from RSU.gen_payload import generate_ssm_payload
    import RSU.main as rsu
    import RSU.parse as parse

    curve, n_ord, G = NIST256p, NIST256p.order, NIST256p.generator
    obu_id_raw = struct.pack('!8s', OBU_ID.encode())

    with open(f"OBU/keys/{OBU_ID}_ecc_priv.key", "rb") as f:
        ecc_sk = SigningKey.from_der(f.read())
    with open(f"OBU/keys/{OBU_ID}_pqc_priv.key", "rb") as f:
        pqc_priv = f.read()
    P_U_bytes, role, pqc_pub, _ = load_cert(OBU_ID)
    pqc_hash  = hashlib.sha256(pqc_pub).digest()

    signer = oqs.Signature(pki.pqc_alg())
    signer.secret_key = create_string_buffer(pqc_priv, len(pqc_priv))
    verifier = oqs.Signature(pki.pqc_alg())

    message  = json.dumps(generate_srm_payload(OBU_ID, intersection_id=RSU_ID), separators=(',', ':')).encode()
    ecc_sig  = ecc_sk.sign(message, hashfunc=hashlib.sha256)
    pqc_sig  = signer.sign(message)
    vk       = parse.reconstruct_obu_pubkey(obu_id_raw, P_U_bytes, pqc_hash, role)

    def fresh(short=False):
        return gen_packet(OBU_ID, intersection_id=RSU_ID, known_RSU=short)

    def reset_rsu(clear_cache=True):
        for d in (rsu.reassemble_buffer, rsu.recent_completed, rsu.recent_granted, rsu.id_active_session, rsu.id_session_meta,
                  rsu.ip_rate_log, rsu.obu_f1_rate_log, rsu.blacklist):
            d.clear()
        if clear_cache:
            parse.clear_all_caches()

    def prewarm():
        parse.inject_prewarm_cache(RSU_ID, obu_id_raw, P_U_bytes, vk, pqc_pub, expire_at=None, role=role)

    # ── 正確性檢查 (不計時)：ECQV 推導出的 d_U 必須與 RSU 重構的 Q_U 對應 ─────────
    k_U, R_U = generate_enrollment_request()
    resp = ca_process_enrollment(obu_id_raw, R_U, pqc_pub, role)
    d_U  = obu_derive_key(obu_id_raw, resp[:33], pqc_pub, int.from_bytes(resp[33:65], "big"), k_U, role)
    q_u  = parse.reconstruct_obu_pubkey(obu_id_raw, resp[:33], pqc_hash, role)
    assert (d_U * G).to_affine() == q_u.pubkey.point.to_affine(), "ECQV 正確性檢查失敗：d_U·G ≠ Q_U"

    items = []

    alg = pki.pqc_alg()

    def add(group, code, desc, category, samples, inner=1):
        # 項目代碼固定 (跨演算法比對用)，說明文字改寫為實際使用的後量子演算法與公鑰長度
        desc = desc.replace("ML-DSA-44", alg).replace("1312B", f"{len(pqc_pub)}B")
        items.append({"group": group, "code": code, "desc": desc, "category": category,
                      "inner": inner, "samples": samples})
        print(f"  [{group:>2}] {code:<40} mean {sum(samples) / len(samples):9.4f} ms", file=sys.stderr)

    # ── 1. CA.enroll：產生 ECQV 資料 ─────────────────────────────────────────
    def prep_enroll(i):
        return (obu_id_raw, generate_enrollment_request()[1], pqc_pub, role)
    add(1, "ca_enroll", "CA ca_process_enrollment total (P_U, e, r; includes CA key file load)", "requested",
        measure(n, ca_process_enrollment, prep_enroll))

    def ca_load_priv():
        with open("CA/keys/ca_ecc_priv.key", "rb") as f:
            serialization.load_der_private_key(f.read(), password=None).private_numbers()
    add(1, "ca_enroll_load_priv_key", "breakdown: read + parse CA ECC private key from disk (every enroll call)",
        "overlooked", measure(n, ca_load_priv))

    def ca_point(R_U):
        from ecdsa.util import randrange
        R = ellipticcurve.PointJacobi.from_bytes(curve.curve, R_U)
        (R + randrange(n_ord) * G).to_bytes("compressed")
    add(1, "ca_enroll_point_ops", "breakdown: P_U = R_U + k_CA*G (decode + scalar mult + add + compress)",
        "overlooked", measure(n, ca_point, lambda i: (generate_enrollment_request()[1],)))

    # ── 2. OBU.setup：推導 d_U ───────────────────────────────────────────────
    def prep_derive(i):
        k_U, R_U = generate_enrollment_request()
        resp = ca_process_enrollment(obu_id_raw, R_U, pqc_pub, role)
        return (obu_id_raw, resp[:33], pqc_pub, int.from_bytes(resp[33:65], "big"), k_U, role)
    add(2, "obu_derive_d_u", "OBU obu_derive_key: d_U = (e*k_U + r) mod n (incl. SHA-256 of 1312B PQC pub)",
        "requested", measure(n, obu_derive_key, prep_derive))
    add(2, "obu_gen_request_r_u", "OBU generate_enrollment_request: k_U random, R_U = k_U*G", "overlooked",
        measure(n, generate_enrollment_request))
    add(2, "obu_signing_key_from_d_u", "OBU SigningKey.from_secret_exponent(d_U) (setup step 5)", "overlooked",
        measure(n, lambda: SigningKey.from_secret_exponent(d_U, curve=NIST256p)))
    add(2, "obu_mldsa_keygen", "OBU ML-DSA-44 keypair generation (setup, one-time)", "overlooked",
        measure(n, lambda: oqs.Signature(pki.pqc_alg()).generate_keypair()))

    # ── 3. 雙層雜湊 e：預雜湊 (73B) vs 直接串接 1312B 公鑰 (1353B) ─────────────
    INNER = 200
    add(3, "e_concat_prehashed_73B", "memory copy: ID(8)+P_U(33)+H(pk)(32) = 73B", "requested",
        measure(n, lambda: obu_id_raw + P_U_bytes + pqc_hash, inner=INNER), INNER)
    add(3, "e_concat_direct_1353B", "memory copy: ID(8)+P_U(33)+pk(1312) = 1353B", "requested",
        measure(n, lambda: obu_id_raw + P_U_bytes + pqc_pub, inner=INNER), INNER)

    def e_from(data):
        return int(hashlib.sha256(data).hexdigest(), 16) % n_ord
    add(3, "e_two_layer_rsu", "e with H(pk) already in packet (RSU path): concat 73B + SHA-256 + mod n",
        "requested", measure(n, lambda: e_from(obu_id_raw + P_U_bytes + pqc_hash), inner=INNER), INNER)
    add(3, "e_two_layer_with_prehash", "e incl. computing H(pk) (CA/OBU path): SHA-256(1312B) + concat 73B + SHA-256",
        "requested", measure(n, lambda: e_from(obu_id_raw + P_U_bytes + hashlib.sha256(pqc_pub).digest()),
                             inner=INNER), INNER)
    add(3, "e_direct_1312B", "e without pre-hash: concat 1353B + SHA-256 + mod n", "requested",
        measure(n, lambda: e_from(obu_id_raw + P_U_bytes + pqc_pub), inner=INNER), INNER)
    add(3, "sha256_pqc_pub_1312B", "SHA-256 of 1312B ML-DSA-44 public key alone", "requested",
        measure(n, lambda: hashlib.sha256(pqc_pub).digest(), inner=INNER), INNER)

    # ── 4. RSU reconstruct_obu_pubkey：Q_U = e·P_U + Q_CA ─────────────────────
    add(4, "rsu_reconstruct_q_u", "RSU parse.reconstruct_obu_pubkey total (includes CA pub key file load)",
        "requested", measure(n, lambda: parse.reconstruct_obu_pubkey(obu_id_raw, P_U_bytes, pqc_hash, role)))

    def load_ca_pub():
        with open("RSU/keys/ca_ecc_pub.key", "rb") as f:
            nums = serialization.load_der_public_key(f.read()).public_numbers()
        return ellipticcurve.PointJacobi(curve.curve, nums.x, nums.y, 1)
    Q_CA = load_ca_pub()
    e_val = e_from(obu_id_raw + P_U_bytes + pqc_hash)
    add(4, "rsu_reconstruct_load_ca_pub", "breakdown: read + parse CA pub key from disk (every reconstruct call)",
        "overlooked", measure(n, load_ca_pub))
    add(4, "rsu_reconstruct_point_math", "breakdown: decode P_U + e*P_U + Q_CA", "requested",
        measure(n, lambda: e_val * ellipticcurve.PointJacobi.from_bytes(curve.curve, P_U_bytes) + Q_CA))
    Q_U = e_val * ellipticcurve.PointJacobi.from_bytes(curve.curve, P_U_bytes) + Q_CA
    add(4, "rsu_reconstruct_vk_from_point", "breakdown: VerifyingKey.from_public_point(Q_U)", "overlooked",
        measure(n, lambda: VerifyingKey.from_public_point(Q_U, curve=NIST256p)))

    # ── 5. Tier-1 ECDSA 驗簽 vs Tier-2 ML-DSA-44 驗簽 ─────────────────────────
    add(5, "rsu_ecdsa_verify", "Tier-1 ECDSA P-256 verify (vk.verify, SHA-256)", "requested",
        measure(n, lambda: vk.verify(ecc_sig, message, hashfunc=hashlib.sha256)))
    add(5, "rsu_mldsa_verify", "Tier-2 ML-DSA-44 verify only (reused oqs object)", "requested",
        measure(n, lambda: verifier.verify(message, pqc_sig, pqc_pub)))

    def mldsa_ctx():
        with oqs.Signature(pki.pqc_alg()):
            pass
    add(5, "rsu_oqs_context_create", "oqs.Signature('ML-DSA-44') construct + free (done per verify in parse_packet)",
        "overlooked", measure(n, mldsa_ctx))

    # ── 6. Early-Drop：F1 雜湊承諾踢掉偽造 F2 ───────────────────────────────────
    with contextlib.redirect_stdout(io.StringIO()):
        reset_rsu()
        frags = make_fragments(fresh(), 60001)
        rsu.process_fragment(frags[0], OBU_ADDR, sock=NullSock(), rsu_id=RSU_ID)
    key6 = (60001, OBU_ADDR)
    assert rsu.reassemble_buffer[key6]["fragments"][0] is not None, "Early-Drop 前置：F1 未被接受"
    fake_f2 = frags[1][:4] + os.urandom(len(frags[1]) - 4)

    def prep_fake(i):
        rsu.ip_rate_log.clear()          # 避免 1000 次連發觸發 IP 限流而提前返回
        return ()
    add(6, "rsu_early_drop_fake_f2", "RSU process_fragment(fake F2): rate limit + header + SHA-256 + compare + drop",
        "requested", measure(n, lambda: rsu.process_fragment(fake_f2, OBU_ADDR, sock=None, rsu_id=RSU_ID), prep_fake))
    assert rsu.reassemble_buffer[key6]["fragments"][1] is None, "偽造 F2 不應被暫存"
    exp_h = rsu.reassemble_buffer[key6]["expected_hashes"][2]
    add(6, "rsu_early_drop_hash_core", "core only: SHA-256(fake F2 chunk) != committed hash", "requested",
        measure(n, lambda: hashlib.sha256(fake_f2[4:]).digest() != exp_h, inner=INNER), INNER)

    # ── 7. OBU 簽章 ──────────────────────────────────────────────────────────
    add(7, "obu_ecdsa_sign", "OBU ECDSA P-256 sign (SHA-256)", "requested",
        measure(n, lambda: ecc_sk.sign(message, hashfunc=hashlib.sha256)))
    add(7, "obu_mldsa_sign", "OBU ML-DSA-44 sign only (reused oqs object)", "requested",
        measure(n, lambda: signer.sign(message)))

    def load_obu_keys():
        with open(f"OBU/keys/{OBU_ID}_ecc_priv.key", "rb") as f:
            SigningKey.from_der(f.read())
        with open(f"OBU/keys/{OBU_ID}_pqc_priv.key", "rb") as f:
            f.read()
        with open(f"OBU/cert/{OBU_ID}_cert.bin", "rb") as f:
            f.read()
    add(7, "obu_load_keys_per_packet", "gen_packet reads ECC key + PQC key + cert from disk every packet",
        "overlooked", measure(n, load_obu_keys))
    add(7, "obu_srm_payload_json", "generate SRM payload + json.dumps", "overlooked",
        measure(n, lambda: json.dumps(generate_srm_payload(OBU_ID, intersection_id=RSU_ID), separators=(',', ':'))))
    with contextlib.redirect_stdout(io.StringIO()):
        add(7, "obu_gen_packet_full", "OBU gen_packet total, Full (payload + 2 signatures + file I/O + packing)",
            "overlooked", measure(n, lambda: gen_packet(OBU_ID, intersection_id=RSU_ID, known_RSU=False)))
        add(7, "obu_gen_packet_short", "OBU gen_packet total, Short", "overlooked",
            measure(n, lambda: gen_packet(OBU_ID, intersection_id=RSU_ID, known_RSU=True)))
        pkt_full, pkt_short = fresh(), fresh(True)
    add(7, "obu_make_fragments_full", "OBU make_fragments (DUP/none) Full: split + SHA-256 commitments", "overlooked",
        measure(n, lambda: make_fragments(pkt_full, 1)))
    add(7, "obu_make_fragments_short", "OBU make_fragments (DUP/none) Short", "overlooked",
        measure(n, lambda: make_fragments(pkt_short, 1)))
    add(7, "obu_make_fragments_xor_full", "OBU make_fragments_xor Full: split + commitments + XOR parity (Python loop)",
        "overlooked", measure(n, lambda: make_fragments_xor(pkt_full, 1)))
    add(7, "obu_make_fragments_xor_short", "OBU make_fragments_xor Short", "overlooked",
        measure(n, lambda: make_fragments_xor(pkt_short, 1)))

    # ── 8. F1 完整處理：解析 + ECQV 重構 + ECDSA 驗簽 ─────────────────────────
    def prep_f1(cold):
        def prep(i):
            with contextlib.redirect_stdout(io.StringIO()):
                f1 = make_fragments(fresh(), 1)[0][4:]
            if cold:
                parse.clear_all_caches()
            else:
                prewarm()
            return (f1,)
        return prep
    f1_op = lambda f1: parse.verify_f1_ecc(f1, rsu_id=RSU_ID)
    add(8, "rsu_f1_verify_cold", "RSU verify_f1_ecc, cache miss: parse + 150ms check + ECQV reconstruct + ECDSA verify",
        "requested", measure(n, f1_op, prep_f1(True)))
    add(8, "rsu_f1_verify_hot", "RSU verify_f1_ecc, cache hit (backhaul prewarmed): parse + ECDSA verify", "requested",
        measure(n, f1_op, prep_f1(False)))

    # ── 9. recover_xor_heavy 單片修復 ───────────────────────────────────────────
    def prep_xor(pkt):
        data, parity = make_fragments_xor(pkt, 1)
        f1_size, n_heavy, _ = _xor_layout(pkt)
        heavy = {i: data[i + 1][4:] for i in range(n_heavy)}
        def prep(i):
            miss = i % n_heavy                              # 輪流遺失每一片
            return ({k: v for k, v in heavy.items() if k != miss}, parity[4:], n_heavy, pkt[:f1_size])
        assert recover_xor_heavy(*prep(0)) == pkt, "XOR 還原結果與原封包不符"
        return prep
    add(9, "rsu_xor_recover_full", "RSU recover_xor_heavy, Full (3 heavy fragments, one missing)", "requested",
        measure(n, recover_xor_heavy, prep_xor(pkt_full)))
    add(9, "rsu_xor_recover_short", "RSU recover_xor_heavy, Short (2 heavy fragments, one missing)", "requested",
        measure(n, recover_xor_heavy, prep_xor(pkt_short)))

    # ── 10. 分片重組與雜湊承諾全片比對 ──────────────────────────────────────────
    def prep_reasm(pkt):
        frs = make_fragments(pkt, 1)
        f1_chunk = frs[0][4:]
        nh = f1_chunk[0]
        hashes = {k + 2: f1_chunk[1 + 32 * k: 33 + 32 * k] for k in range(nh)}
        raw_f1 = f1_chunk[1 + 32 * nh:]
        chunks = [fr[4:] for fr in frs[1:]]
        return lambda i: (raw_f1, chunks, hashes)
    def reassemble(raw_f1, chunks, hashes):
        for seq, c in enumerate(chunks, 2):
            if hashlib.sha256(c).digest() != hashes[seq]:
                raise ValueError("hash mismatch")
        return b''.join([raw_f1, *chunks])
    add(10, "rsu_reassembly_full", "verify SHA-256 commitment of every F2..FN + join, Full (3 fragments)",
        "requested", measure(n, reassemble, prep_reasm(pkt_full)))
    add(10, "rsu_reassembly_short", "verify SHA-256 commitment of every F2..FN + join, Short (2 fragments)",
        "requested", measure(n, reassemble, prep_reasm(pkt_short)))

    # ── 11. ML-DSA-44 驗簽：Full 與 Short 分開 ─────────────────────────────────
    def mldsa_with_ctx(pk):
        with oqs.Signature(pki.pqc_alg()) as v:
            v.verify(message, pqc_sig, pk)
    pk_off = pkt_full.find(pqc_pub)
    assert pk_off > 0, "Full 封包中找不到 PQC 公鑰"
    add(11, "rsu_mldsa_verify_full", "ML-DSA-44 verify as in parse_packet, Full: pk sliced from packet (incl. oqs ctx)",
        "requested", measure(n, lambda: mldsa_with_ctx(pkt_full[pk_off:pk_off + len(pqc_pub)])))
    prewarm()
    add(11, "rsu_mldsa_verify_short", "ML-DSA-44 verify as in parse_packet, Short: pk from cache lookup (incl. oqs ctx)",
        "requested", measure(n, lambda: mldsa_with_ctx(parse.query_pqc_pub_cache(obu_id_raw, rsu_id=RSU_ID))))
    add(11, "rsu_full_pk_hash_binding", "Full only: SHA-256(1312B pk) == pqc_pub_hash check", "requested",
        measure(n, lambda: hashlib.sha256(pqc_pub).digest() == pqc_hash, inner=INNER), INNER)
    add(11, "rsu_short_cache_lookup", "Short only: query_pqc_pub_cache", "requested",
        measure(n, lambda: parse.query_pqc_pub_cache(obu_id_raw, rsu_id=RSU_ID), inner=INNER), INNER)

    def prep_parse(short):
        def prep(i):
            reset_rsu()
            prewarm()                     # ECQV 公鑰快取命中，聚焦於雙簽驗證差異
            return (pkt_short if short else pkt_full,)
        return prep
    with contextlib.redirect_stdout(io.StringIO()):
        add(11, "rsu_parse_packet_full", "RSU parse_packet total, Full (hash binding + ML-DSA + ECDSA + cache write)",
            "requested", measure(n, lambda p: parse.parse_packet(p, rsu_id=RSU_ID), prep_parse(False)))
        add(11, "rsu_parse_packet_short", "RSU parse_packet total, Short (cache lookup + ML-DSA + ECDSA)",
            "requested", measure(n, lambda p: parse.parse_packet(p, rsu_id=RSU_ID), prep_parse(True)))

    # ── 其他被忽略的 RSU 成本 ─────────────────────────────────────────────────
    add(0, "rsu_ssm_generate_json", "RSU generate_ssm_payload + json.dumps (green SSM)", "overlooked",
        measure(n, lambda: json.dumps(generate_ssm_payload(obu_id=OBU_ID, intersection_id=RSU_ID, status=4,
                                                           prewarmed_rsus=[2, 3]), separators=(',', ':'))))
    with contextlib.redirect_stdout(io.StringIO()):
        add(0, "rsu_backhaul_prewarm", "RSU trigger_inter_rsu_prewarm to downstream RSUs (2 and 3)", "overlooked",
            measure(n, lambda: rsu.trigger_inter_rsu_prewarm(RSU_ID, obu_id_raw, P_U_bytes, vk, pqc_pub, role=role)))

    # 端到端：整則訊息經過真實 process_fragment，直到送出綠燈 SSM
    def prep_e2e(short, mode):
        def prep(i):
            with contextlib.redirect_stdout(io.StringIO()):
                pkt = fresh(short)
            reset_rsu()
            if short:
                prewarm()
            if mode == "xor":
                data, parity = make_fragments_xor(pkt, 50000 + i)
                frs = [data[0], *data[2:], parity]          # F2 遺失，以 FP 修復
            else:
                frs = make_fragments(pkt, 50000 + i)
            return (frs, NullSock())
        return prep
    def e2e(frs, sock):
        for f in frs:
            rsu.process_fragment(f, OBU_ADDR, sock=sock, rsu_id=RSU_ID)
        if not sock.sent:
            raise RuntimeError("未產生 SSM")
    with contextlib.redirect_stdout(open(os.devnull, "w")):
        add(0, "rsu_message_e2e_full_cold", "RSU whole message to green SSM, Full, cold cache (all real code paths)",
            "overlooked", measure(n, e2e, prep_e2e(False, "none")))
        add(0, "rsu_message_e2e_short_prewarmed", "RSU whole message to green SSM, Short, backhaul-prewarmed cache",
            "overlooked", measure(n, e2e, prep_e2e(True, "none")))
        add(0, "rsu_message_e2e_xor_full_recover", "RSU whole message to green SSM, XOR Full with F2 lost + recovered",
            "overlooked", measure(n, e2e, prep_e2e(False, "xor")))

    add(0, "timer_overhead", "perf_counter_ns call pair with empty op (measurement floor)", "overlooked",
        measure(n, lambda: None))

    # ── 參考對照：同為 P-256 ECDSA，改用 OpenSSL 實作 (cryptography 套件) ──────────
    # 專案使用純 Python 的 ecdsa 套件，此兩項僅供評估「換成 C 實作可省多少時間」，不在系統流程中
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    ossl_sk  = ec.generate_private_key(ec.SECP256R1())
    ossl_pk  = ossl_sk.public_key()
    ossl_sig = ossl_sk.sign(message, ec.ECDSA(hashes.SHA256()))
    add(0, "ref_ecdsa_sign_openssl", "reference only: P-256 ECDSA sign via OpenSSL (cryptography)", "reference",
        measure(n, lambda: ossl_sk.sign(message, ec.ECDSA(hashes.SHA256()))))
    add(0, "ref_ecdsa_verify_openssl", "reference only: P-256 ECDSA verify via OpenSSL (cryptography)", "reference",
        measure(n, lambda: ossl_pk.verify(ossl_sig, message, ec.ECDSA(hashes.SHA256()))))
    return items


def _stats(s):
    s2 = sorted(s)
    pct = lambda p: s2[min(len(s2) - 1, int(round((len(s2) - 1) * p / 100)))]
    mean = sum(s2) / len(s2)
    std = (sum((x - mean) ** 2 for x in s2) / (len(s2) - 1)) ** 0.5 if len(s2) > 1 else 0.0
    r = lambda v: round(v, 6)
    return {"n": len(s2), "mean": r(mean), "std": r(std), "min": r(s2[0]), "p50": r(pct(50)),
            "p95": r(pct(95)), "p99": r(pct(99)), "max": r(s2[-1])}


def _write_csv(path, rows, headers):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(headers.values())
        for row in rows:
            # 浮點數固定 6 位小數 (ms → 精確到 ns)，避免 Excel 顯示 7.6e-05 這類科學記號
            w.writerow(f"{row[k]:.6f}" if isinstance(row[k], float) else row[k] for k in headers)


def main():
    ap = argparse.ArgumentParser(description="系統運算耗時量測")
    ap.add_argument("--iterations", type=int, default=1000, help="每項量測次數 (預設 1000)")
    ap.add_argument("--out", default=None, help="輸出目錄 (預設為 sim/results/ 底下下一個未使用的編號資料夾)")
    args = ap.parse_args()
    out = args.out or _next_run_dir()
    os.makedirs(out, exist_ok=True)

    t0 = time.perf_counter()
    print(f"量測中，每項 {args.iterations} 次 …", file=sys.stderr)
    with open(os.devnull, "w") as devnull, contextlib.redirect_stdout(devnull):   # RSU/OBU 會大量 print
        items = run(args.iterations)
    elapsed = time.perf_counter() - t0

    summary = [{**{k: it[k] for k in ("group", "code", "desc", "category", "inner")}, **_stats(it["samples"])}
               for it in items]
    samples = [{"group": it["group"], "code": it["code"], "iteration": i + 1, "ms": round(v, 6)}
               for it in items for i, v in enumerate(it["samples"])]
    _write_csv(os.path.join(out, "compute_summary.csv"), summary, SUMMARY_HEADERS)
    _write_csv(os.path.join(out, "compute_samples.csv"), samples, SAMPLE_HEADERS)

    import oqs, ecdsa, cryptography
    params = {
        "command": " ".join(["python3 -m sim.bench_compute", *sys.argv[1:]]),
        "git_commit": _git_commit(),
        "run_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed_s": round(elapsed, 1),
        "iterations": args.iterations, "warmup": 20, "gc_disabled_during_timing": True,
        "inner_repeat_for_sub_microsecond_items": 200,
        "python": sys.version.split()[0], "platform": platform.platform(),
        "machine": platform.machine(), "processor": platform.processor(),
        "liboqs_python": getattr(oqs, "__version__", ""), "liboqs": oqs.oqs_version() if hasattr(oqs, "oqs_version") else "",
        "ecdsa": ecdsa.__version__, "cryptography": cryptography.__version__,
        "pqc_alg": pki.pqc_alg(),
    }
    with open(os.path.join(out, "params.json"), "w", encoding="utf-8") as f:
        json.dump(params, f, ensure_ascii=False, indent=2)
    print(f"完成 ({elapsed:.1f}s)，輸出至 {out}/", file=sys.stderr)


if __name__ == "__main__":
    main()
