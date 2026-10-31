"""
攻擊模擬測試：對真實 OBU / RSU 程式碼發動偽造、竄改、冒充、重放、量子攻擊者等攻擊，
確認 RSU 是否拒絕 (不閃黃燈 / 不觸發綠燈 / 不誤封鎖合法車輛)。

每項測試：
  1. 重設 RSU 狀態 (緩衝區、快取、黑名單、限流紀錄)
  2. 以攻擊者能力構造封包 (只使用該攻擊者實際能取得的金鑰與資料)
  3. 逐片送入真實的 RSU.main.process_fragment，記錄是否閃黃燈、是否回綠燈 SSM、是否觸發黑名單
  4. 必要時再送一則合法訊息，檢查合法車輛是否被連帶影響 (誤封鎖 / 被搶占)
  5. 與預期比對：defended = 攻擊未得逞且合法車輛未受影響

輸出：security/results/attack_results.csv (欄位中文，內容英文代碼)

用法 (於專案根目錄，需先完成 CA / RSU / OBU setup)：
  python3 -m security.attack_tests
"""
import contextlib, csv, hashlib, io, json, os, struct, sys, time
from ctypes import create_string_buffer

import oqs
from ecdsa import SigningKey, NIST256p
from ecdsa.util import randrange
from cryptography.hazmat.primitives import serialization

from CA.listen import handle_enrollment
from CA.registry import load_registry
from OBU.setup import generate_enrollment_request, obu_derive_key
from OBU.encode_packet import load_cert
from OBU.gen_payload import generate_srm_payload
from OBU.fragment import make_fragments
from fec import make_fragments_xor
import OBU.main as obu
import RSU.main as rsu
import RSU.parse as parse
import pki

OBU_ID     = "AMB-217"
RSU_ID     = 1
LEGIT_ADDR = ("10.0.0.2", 40000)
ATK_ADDR   = ("10.6.6.6", 46666)
PQC_ALG    = pki.pqc_alg()
curve, G, N = NIST256p, NIST256p.generator, NIST256p.order


# ─── 金鑰與封包工具 ─────────────────────────────────────────────────────────
class Identity:
    """一組車輛身分：ID、角色、ECC 私鑰 d_U、ECQV 重構點 P_U、ML-DSA 金鑰對、CA 後量子憑證。"""
    def __init__(self, obu_id, role, ecc_sk, P_U, pqc_pub, pqc_priv, ca_cert):
        self.obu_id, self.role, self.ecc_sk, self.P_U = obu_id, role, ecc_sk, P_U
        self.pqc_pub, self.pqc_priv, self.ca_cert = pqc_pub, pqc_priv, ca_cert
        self.id_raw = struct.pack('!8s', obu_id.encode())

    @property
    def pqc_hash(self):
        return hashlib.sha256(self.pqc_pub).digest()


def load_legit():
    with open(f"OBU/keys/{OBU_ID}_ecc_priv.key", "rb") as f:
        sk = SigningKey.from_der(f.read())
    with open(f"OBU/keys/{OBU_ID}_pqc_priv.key", "rb") as f:
        pqc_priv = f.read()
    P_U, role, pqc_pub, ca_cert = load_cert(OBU_ID)
    return Identity(OBU_ID, role, sk, P_U, pqc_pub, pqc_priv, ca_cert)


def new_pqc_keypair():
    s = oqs.Signature(PQC_ALG)
    pub = s.generate_keypair()
    return pub, s.export_secret_key()


def enroll_request(obu_id, enroll_key, registry):
    """依 OBU/setup.py 的流程向 CA (CA.listen.handle_enrollment) 註冊；被拒絕時回傳 None。"""
    pqc_pub, pqc_priv = new_pqc_keypair()
    id_raw = struct.pack('!8s', obu_id.encode())
    k_U, R_U = generate_enrollment_request()
    resp = handle_enrollment(id_raw, R_U, pqc_pub, pki.enroll_mac(enroll_key, id_raw, R_U, pqc_pub), registry=registry)
    if resp is None:
        return None
    P_U, role = resp[:33], resp[65]
    cert_len = struct.unpack('!H', resp[66:68])[0]
    d_U = obu_derive_key(id_raw, P_U, pqc_pub, int.from_bytes(resp[33:65], "big"), k_U, role)
    return Identity(obu_id, role, SigningKey.from_secret_exponent(d_U, curve=NIST256p), P_U, pqc_pub, pqc_priv,
                    resp[68:68 + cert_len])


def enroll_registered(obu_id, role=pki.ROLE_BASIC_VEHICLE):
    """在 CA 名冊合法登記一台車並完成註冊 (攻擊者控制的已註冊車輛)。"""
    key = os.urandom(32)
    return enroll_request(obu_id, key, {obu_id: {"role": role, "enroll_key": key.hex()}})


def forge_ecqv_with_ca_key(obu_id, d_CA, role=pki.ROLE_AMBULANCE):
    """
    量子攻擊者以 Shor 演算法自 Q_CA 求得 CA 私鑰 d_CA 後，離線自行簽發 ECQV 隱式憑證：
    P_U = k·G，e = H(ID ‖ role ‖ P_U ‖ H(pk_PQC))，d_U = e·k + d_CA  → Q_U = e·P_U + Q_CA = d_U·G 成立。
    CA 的 ML-DSA 根金鑰無法破解，攻擊者只能附上別人的 CA 後量子憑證。
    """
    pqc_pub, pqc_priv = new_pqc_keypair()
    id_raw = struct.pack('!8s', obu_id.encode())
    k = randrange(N)
    P_U = (k * G).to_bytes("compressed")
    e = pki.ecqv_e(id_raw, role, P_U, hashlib.sha256(pqc_pub).digest())
    d_U = (e * k + d_CA) % N
    return Identity(obu_id, role, SigningKey.from_secret_exponent(d_U, curve=NIST256p), P_U, pqc_pub, pqc_priv, b"")


def srm_bytes(obu_id=OBU_ID, ts=None, intersection_id=RSU_ID, **overrides):
    payload = generate_srm_payload(obu_id, intersection_id=intersection_id, sim_time=ts if ts is not None else time.time())
    payload.update(overrides)
    return json.dumps(payload, separators=(',', ':')).encode()


def ecc_sign(sk, msg, pqc_sig):
    """OBU 的 ECC 簽章涵蓋 payload ‖ H(sig_PQC) (F-1)。"""
    return sk.sign(pki.obu_ecc_tbs(msg, hashlib.sha256(pqc_sig).digest()), hashfunc=hashlib.sha256)


def pqc_sign(priv, msg):
    with oqs.Signature(PQC_ALG) as s:
        s.secret_key = create_string_buffer(priv, len(priv))
        return s.sign(msg)


def assemble(msg, ecc_sig, ident, pqc_sig, short=False, pqc_hash=None, pqc_pub=None, ca_cert=None, pqc_sig_hash=None):
    """依 OBU/encode_packet.py 的格式組裝封包；欄位預設取自 ident，可逐一覆寫以構造攻擊。"""
    pqc_hash = ident.pqc_hash if pqc_hash is None else pqc_hash
    pqc_pub = ident.pqc_pub if pqc_pub is None else pqc_pub
    ca_cert = ident.ca_cert if ca_cert is None else ca_cert
    pqc_sig_hash = hashlib.sha256(pqc_sig).digest() if pqc_sig_hash is None else pqc_sig_hash
    pub_part = struct.pack('!H', 0) if short else (struct.pack('!H', len(pqc_pub)) + pqc_pub
                                                   + struct.pack('!H', len(ca_cert)) + ca_cert)
    return (struct.pack('!H', len(msg)) + msg + struct.pack('!B', len(ecc_sig)) + ecc_sig
            + ident.id_raw + bytes([ident.role]) + ident.P_U + pqc_hash + pqc_sig_hash
            + pub_part + struct.pack('!H', len(pqc_sig)) + pqc_sig)


def honest_packet(ident, short=False, msg=None):
    msg = msg or srm_bytes(ident.obu_id)
    pqc_sig = pqc_sign(ident.pqc_priv, msg)
    return assemble(msg, ecc_sign(ident.ecc_sk, msg, pqc_sig), ident, pqc_sig, short=short)


def recommit(frags):
    """中間人改寫後續分片後，重新計算 F1 內的雜湊承諾 (承諾本身不受簽章保護)。"""
    seq, total, msg_id = struct.unpack('!BBH', frags[0][:4])
    f1 = frags[0][4:]
    nh = f1[0]
    hashes = b''.join(hashlib.sha256(f[4:]).digest() for f in frags[1:])
    return [frags[0][:4] + bytes([nh]) + hashes + f1[1 + 32 * nh:]] + frags[1:]


def flip(b, i):
    return b[:i] + bytes([b[i] ^ 0x01]) + b[i + 1:]


# ─── RSU 驅動 ───────────────────────────────────────────────────────────────
class CaptureSock:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        ssm = json.loads(data)
        # 每則下行 SSM 都必須能通過 OBU 端驗證 (F-6)，否則合法車輛會忽略它
        assert obu.ssm_trusted(ssm), "RSU 送出的 SSM 未通過 OBU 驗證"
        self.sent.append((addr, ssm))


_msg_id = [1000]

def next_msg_id():
    _msg_id[0] += 1
    return _msg_id[0]


def reset_rsu():
    for d in (rsu.reassemble_buffer, rsu.recent_completed, rsu.recent_granted, rsu.id_active_session,
              rsu.id_session_meta, rsu.ip_rate_log, rsu.obu_f1_rate_log, rsu.blacklist):
        d.clear()
    parse.clear_all_caches()


def prewarm(ident):
    vk = parse.reconstruct_obu_pubkey(ident.id_raw, ident.P_U, ident.pqc_hash, ident.role)
    parse.inject_prewarm_cache(RSU_ID, ident.id_raw, ident.P_U, vk, ident.pqc_pub, expire_at=None, role=ident.role)


def deliver(frags, addr, sock):
    """送入分片，回傳 {'flash': bool, 'green': bool, 'nack': bool}。"""
    msg_id = struct.unpack('!BBH', frags[0][:4])[2]
    before = len(sock.sent)
    flash = False
    for f in frags:
        rsu.process_fragment(f, addr, sock=sock, rsu_id=RSU_ID)
        key = (msg_id, addr)
        if (key in rsu.reassemble_buffer and rsu.reassemble_buffer[key]["fragments"][0] is not None) \
                or key in rsu.recent_completed:
            flash = True
    statuses = [st["sigStatus"][0]["status"] for a, ssm in sock.sent[before:] if a == addr
                for st in ssm["status"]]
    return {"flash": flash, "green": 4 in statuses, "nack": 6 in statuses}


def legit_followup(legit, sock, short=False):
    """攻擊後再送一則合法訊息，確認合法車輛不受影響。"""
    time.sleep(0.01)
    return deliver(make_fragments(honest_packet(legit, short), next_msg_id()), LEGIT_ADDR, sock)


# ─── 測試案例 ──────────────────────────────────────────────────────────────
TESTS = []

def case(tid, threat, attacker, mechanism):
    def deco(fn):
        TESTS.append({"id": tid, "threat": threat, "attacker": attacker, "mechanism": mechanism, "fn": fn})
        return fn
    return deco


@case("B1", "baseline", "none", "legit Full message accepted; signed SSM verified by OBU")
def t_b1(legit, sock):
    r = deliver(make_fragments(honest_packet(legit), next_msg_id()), LEGIT_ADDR, sock)
    return r["green"], f"green={r['green']}", True


@case("B2", "baseline", "none", "legit Short message accepted with backhaul-prewarmed cache")
def t_b2(legit, sock):
    prewarm(legit)
    r = deliver(make_fragments(honest_packet(legit, short=True), next_msg_id()), LEGIT_ADDR, sock)
    return r["green"], f"green={r['green']}", True


@case("F1", "forgery", "no keys; forges AMB-217 SRM with random ECC key + legit public cert fields",
      "F1 ECDSA verify under ECQV-reconstructed Q_U")
def t_f1(legit, sock):
    fake_sk = SigningKey.generate(curve=NIST256p)
    _, fake_pqc_priv = new_pqc_keypair()
    msg = srm_bytes()
    sig = pqc_sign(fake_pqc_priv, msg)
    pkt = assemble(msg, ecc_sign(fake_sk, msg, sig), legit, sig)
    r = deliver(make_fragments(pkt, next_msg_id()), ATK_ADDR, sock)
    f = legit_followup(legit, sock)
    return not r["flash"] and not r["green"] and f["green"], f"atk flash={r['flash']} green={r['green']}; legit green={f['green']}", True


@case("T1", "tampering", "MITM modifies SRM field (intersection id) after signing",
      "ECDSA signature covers SRM payload")
def t_t1(legit, sock):
    msg = srm_bytes()
    pkt = honest_packet(legit, msg=msg)
    tampered = msg.replace(b'"id":{"id":1}', b'"id":{"id":9}')
    assert tampered != msg
    pkt = pkt.replace(msg, tampered)
    r = deliver(make_fragments(pkt, next_msg_id()), ATK_ADDR, sock)
    return not r["flash"] and not r["green"], f"flash={r['flash']} green={r['green']}", True


@case("T2", "tampering", "MITM flips one byte of the ECDSA signature", "ECDSA verify")
def t_t2(legit, sock):
    msg = srm_bytes()
    pkt = honest_packet(legit, msg=msg)
    pkt = flip(pkt, 2 + len(msg) + 5)
    r = deliver(make_fragments(pkt, next_msg_id()), ATK_ADDR, sock)
    return not r["flash"] and not r["green"], f"flash={r['flash']} green={r['green']}", True


@case("T3", "tampering", "MITM flips a byte of the ML-DSA signature in a heavy fragment (commitment untouched)",
      "F1 SHA-256 fragment commitment (Early-Drop)")
def t_t3(legit, sock):
    frags = make_fragments(honest_packet(legit), next_msg_id())
    frags[-1] = flip(frags[-1], len(frags[-1]) - 10)
    r = deliver(frags, ATK_ADDR, sock)
    f = legit_followup(legit, sock)
    return not r["green"] and not rsu.blacklist and f["green"], \
        f"atk green={r['green']}; blacklist={list(rsu.blacklist)}; legit green={f['green']}", True


@case("T4", "tampering", "MITM swaps PQC public key (Full) and recomputes F1 commitments",
      "pqc_pub_hash bound into ECQV e; SHA-256 binding check")
def t_t4(legit, sock):
    other_pub, _ = new_pqc_keypair()
    pkt = honest_packet(legit).replace(legit.pqc_pub, other_pub)
    frags = recommit(make_fragments(pkt, next_msg_id()))
    r = deliver(frags, ATK_ADDR, sock)
    f = legit_followup(legit, sock)
    return not r["green"] and not rsu.blacklist and f["green"], \
        f"atk flash={r['flash']} green={r['green']}; blacklist={list(rsu.blacklist)}; legit green={f['green']}", True


@case("T5", "tampering / DoS", "MITM relays legit F1 but corrupts ML-DSA sig and recomputes F1 commitments",
      "F-1: ECC signs payload || H(sig_PQC) -> PQC_SIG_HASH_MISMATCH, dropped without blacklisting")
def t_t5(legit, sock):
    frags = make_fragments(honest_packet(legit), next_msg_id())
    frags[-1] = flip(frags[-1], len(frags[-1]) - 10)
    frags = recommit(frags)
    r = deliver(frags, ATK_ADDR, sock)
    status = parse.LAST_PARSE_STATUS
    banned = OBU_ID in rsu.blacklist
    f = legit_followup(legit, sock)
    return not r["green"] and not banned and f["green"], \
        f"atk green={r['green']} status={status}; AMB-217 blacklisted={banned}; legit green after attack={f['green']}", True


@case("T6", "tampering", "inject forged F2 with valid header into legit session", "Early-Drop hash commitment")
def t_t6(legit, sock):
    msg_id = next_msg_id()
    frags = make_fragments(honest_packet(legit), msg_id)
    fake = frags[1][:4] + os.urandom(len(frags[1]) - 4)
    rsu.process_fragment(frags[0], LEGIT_ADDR, sock=sock, rsu_id=RSU_ID)
    rsu.process_fragment(fake, LEGIT_ADDR, sock=sock, rsu_id=RSU_ID)
    r = deliver(frags[1:], LEGIT_ADDR, sock)
    return r["green"], f"legit green despite injected F2={r['green']}", True


@case("T7", "tampering", "poisoned XOR parity fragment arrives before the real one",
      "recovered fragment checked against F1 commitment; poisoned FP discarded")
def t_t7(legit, sock):
    data, parity = make_fragments_xor(honest_packet(legit), next_msg_id())
    fake_fp = parity[:12] + bytes(len(parity) - 12)
    rsu.process_fragment(fake_fp, LEGIT_ADDR, sock=sock, rsu_id=RSU_ID)
    r = deliver([*data[:-1], parity], LEGIT_ADDR, sock)          # 最後一片遺失，需用真 FP 修復
    return r["green"], f"legit green after poisoned FP={r['green']}", True


@case("T8", "tampering / cache poisoning", "cache warm; MITM relays legit SRM + ECC sig but swaps in attacker "
      "pqc_pub_hash, PQC key and ML-DSA sig", "F-7: ECQV key cache keyed by (ID, role, P_U, H(pk)); F-1/F-5 bindings")
def t_t8(legit, sock):
    deliver(make_fragments(honest_packet(legit), next_msg_id()), LEGIT_ADDR, sock)      # 快取已暖
    pub, priv = new_pqc_keypair()
    msg = srm_bytes()
    legit_sig = pqc_sign(legit.pqc_priv, msg)
    atk_sig = pqc_sign(priv, msg)
    pkt = assemble(msg, ecc_sign(legit.ecc_sk, msg, legit_sig), legit, atk_sig,   # 中間人只能轉送合法 ECC 簽章
                   pqc_hash=hashlib.sha256(pub).digest(), pqc_pub=pub, pqc_sig_hash=hashlib.sha256(atk_sig).digest())
    r = deliver(make_fragments(pkt, next_msg_id()), ATK_ADDR, sock)
    poisoned = parse.query_pqc_pub_cache(legit.id_raw, rsu_id=RSU_ID) == pub
    f = legit_followup(legit, sock, short=True)
    return not r["green"] and not poisoned and f["green"], \
        f"atk green={r['green']}; PQC cache poisoned={poisoned}; legit Short green={f['green']}", True


@case("I1", "impersonation", "enrolled attacker (EVIL-01) signs with own key but claims ID AMB-217",
      "ECQV: Q_U reconstructed from claimed ID -> attacker key does not match")
def t_i1(legit, sock):
    evil = enroll_registered("EVIL-01")
    msg = srm_bytes()
    sig = pqc_sign(evil.pqc_priv, msg)
    pkt = assemble(msg, ecc_sign(evil.ecc_sk, msg, sig), legit, sig, pqc_hash=evil.pqc_hash, pqc_pub=evil.pqc_pub,
                   ca_cert=evil.ca_cert)
    pkt = pkt.replace(legit.P_U, evil.P_U)
    r = deliver(make_fragments(pkt, next_msg_id()), ATK_ADDR, sock)
    return not r["flash"] and not r["green"], f"flash={r['flash']} green={r['green']}", True


@case("I2", "impersonation", "enrolled attacker reuses AMB-217's P_U / pk hash with own ECC key",
      "ECQV implicit certificate binds d_U to (ID, role, P_U, H(pk))")
def t_i2(legit, sock):
    evil = enroll_registered("EVIL-01")
    msg = srm_bytes()
    sig = pqc_sign(evil.pqc_priv, msg)
    pkt = assemble(msg, ecc_sign(evil.ecc_sk, msg, sig), legit, sig)
    r = deliver(make_fragments(pkt, next_msg_id()), ATK_ADDR, sock)
    return not r["flash"] and not r["green"], f"flash={r['flash']} green={r['green']}", True


@case("I3", "impersonation / authorization", "enrolled NON-emergency vehicle (role=0) sends SRM claiming role=ambulance",
      "F-2: role bound into ECQV e and CA PQC cert; RSU requires emergency role matching the SRM")
def t_i3(legit, sock):
    car = enroll_registered("CAR-0042", role=pki.ROLE_BASIC_VEHICLE)
    r1 = deliver(make_fragments(honest_packet(car), next_msg_id()), ATK_ADDR, sock)     # 憑證角色 0，SRM 自稱 14
    car.role = pki.ROLE_AMBULANCE                                                         # 再竄改封包內的角色欄位
    r2 = deliver(make_fragments(honest_packet(car), next_msg_id()), ATK_ADDR, sock)
    return not r1["green"] and not r2["green"] and not r1["flash"] and not r2["flash"], \
        f"cert role=0: flash={r1['flash']} green={r1['green']}; role byte forged to 14: flash={r2['flash']} green={r2['green']}", True


@case("I4", "impersonation / enrollment", "attacker asks the CA to enroll ID AMB-217 (and an unregistered ID) "
      "without the enrollment key", "F-3: CA registry + HMAC-authenticated enrollment request")
def t_i4(legit, sock):
    registry = load_registry()
    clone = enroll_request(OBU_ID, os.urandom(32), registry)
    stranger = enroll_request("AMB-999", os.urandom(32), registry)
    return clone is None and stranger is None, \
        f"AMB-217 credential issued={clone is not None}; unregistered AMB-999 issued={stranger is not None}", True


@case("I5", "DoS / framing", "attacker floods invalid F1s claiming AMB-217 to get it blacklisted",
      "no blacklisting before authentication")
def t_i5(legit, sock):
    fake_sk = SigningKey.generate(curve=NIST256p)
    for _ in range(20):
        msg = srm_bytes()
        sig = b"\x00" * 2420
        pkt = assemble(msg, ecc_sign(fake_sk, msg, sig), legit, sig)
        deliver(make_fragments(pkt, next_msg_id())[:1], ATK_ADDR, sock)
    f = legit_followup(legit, sock)
    return f["green"] and not rsu.blacklist, f"blacklist={list(rsu.blacklist)}; legit green={f['green']}", True


@case("R1", "replay", "replay captured legit message after 200 ms", "150 ms freshness check on full_timestamp")
def t_r1(legit, sock):
    frags = make_fragments(honest_packet(legit), next_msg_id())
    time.sleep(0.2)
    r = deliver(frags, ATK_ADDR, sock)
    return not r["flash"] and not r["green"], f"flash={r['flash']} green={r['green']}", True


@case("R2", "replay", "replay within 150 ms from another address while the legit session is in progress",
      "per-vehicle session dedup by F1 timestamp")
def t_r2(legit, sock):
    msg_id = next_msg_id()
    frags = make_fragments(honest_packet(legit), msg_id)
    rsu.process_fragment(frags[0], LEGIT_ADDR, sock=sock, rsu_id=RSU_ID)
    r = deliver(frags, ATK_ADDR, sock)
    f = deliver(frags[1:], LEGIT_ADDR, sock)
    return not r["green"] and f["green"], f"replay green={r['green']}; legit green={f['green']}", True


@case("R3", "replay", "replay within 150 ms from another address AFTER the legit session completed",
      "F-4: granted SRMs remembered by (obu_id, full_timestamp)")
def t_r3(legit, sock):
    frags = make_fragments(honest_packet(legit), next_msg_id())
    first = deliver(frags, LEGIT_ADDR, sock)
    r = deliver(frags, ATK_ADDR, sock)
    return first["green"] and not r["green"], f"legit green={first['green']}; replay green={r['green']}", True


@case("R4", "replay / wormhole", "legit SRM addressed to intersection 2 relayed to RSU 1 within 150 ms",
      "F-8: SRM target intersection must equal the receiving RSU")
def t_r4(legit, sock):
    msg = srm_bytes(intersection_id=2)
    r = deliver(make_fragments(honest_packet(legit, msg=msg), next_msg_id()), ATK_ADDR, sock)
    f = legit_followup(legit, sock)
    return not r["flash"] and not r["green"] and f["green"], \
        f"relayed flash={r['flash']} green={r['green']}; legit green={f['green']}", True


@case("D1", "DoS (crash)", "single forged fragment opens the session with a smaller total_frags before the legit F1",
      "fragment count taken from authenticated F1; receive_data catches per-packet exceptions")
def t_d1(legit, sock):
    msg_id = next_msg_id()
    frags = make_fragments(honest_packet(legit), msg_id)
    try:
        rsu.process_fragment(struct.pack('!BBH', 2, 2, msg_id) + os.urandom(40), LEGIT_ADDR, sock=sock, rsu_id=RSU_ID)
        r = deliver(frags, LEGIT_ADDR, sock)
    except Exception as e:
        return False, f"RSU raised {type(e).__name__}: {e}", True
    return r["green"], f"no crash; legit green={r['green']}", True


@case("D2", "DoS (memory / eviction)", "after legit F1, attacker opens 150 fake sessions from spoofed IPs (pool cap 100)",
      "100-slot pool evicts unauthenticated sessions first")
def t_d2(legit, sock):
    msg_id = next_msg_id()
    frags = make_fragments(honest_packet(legit), msg_id)
    rsu.process_fragment(frags[0], LEGIT_ADDR, sock=sock, rsu_id=RSU_ID)
    for i in range(150):
        rsu.process_fragment(struct.pack('!BBH', 2, 5, 30000 + i) + b"x" * 8,
                             (f"172.16.{i // 200}.{i % 200 + 1}", 50000 + i), sock=sock, rsu_id=RSU_ID)
    pool = len(rsu.reassemble_buffer)
    r = deliver(frags[1:], LEGIT_ADDR, sock)
    return r["green"] and pool <= rsu.MAX_SESSIONS, f"pool={pool}; legit green={r['green']}", True


@case("D3", "DoS (rate-limit abuse)", "attacker spoofs AMB-217's IP and sends 80 junk fragments between F1 and the tail",
      "source-IP rate limit applies to F1 only")
def t_d3(legit, sock):
    msg_id = next_msg_id()
    frags = make_fragments(honest_packet(legit), msg_id)
    rsu.process_fragment(frags[0], LEGIT_ADDR, sock=sock, rsu_id=RSU_ID)
    for i in range(80):
        rsu.process_fragment(struct.pack('!BBH', 2, 5, 40000 + i) + b"j" * 8, (LEGIT_ADDR[0], 1000 + i),
                             sock=sock, rsu_id=RSU_ID)
    r = deliver(frags[1:], LEGIT_ADDR, sock)
    return r["green"], f"legit green after IP-spoof flood={r['green']}", True


@case("D4", "DoS (pre-F1 overwrite)", "primary F1 lost; tail arrives first and attacker re-sends 3 forged copies of "
      "each tail fragment before the backup F1", "pre-F1 candidates per slot, first arrival always kept")
def t_d4(legit, sock):
    msg_id = next_msg_id()
    frags = make_fragments(honest_packet(legit), msg_id)
    for f in frags[1:]:
        rsu.process_fragment(f, LEGIT_ADDR, sock=sock, rsu_id=RSU_ID)
        for _ in range(3):
            rsu.process_fragment(f[:4] + os.urandom(len(f) - 4), LEGIT_ADDR, sock=sock, rsu_id=RSU_ID)
    r = deliver(frags[:1], LEGIT_ADDR, sock)
    return r["green"], f"legit green with backup F1={r['green']}", True


@case("S1", "forged downlink", "attacker sends unsigned / self-signed SSM status=6 to force Full fallback",
      "F-6: OBU verifies RSU certificate (CA ECC) + SSM ECDSA signature")
def t_s1(legit, sock):
    from RSU.gen_payload import generate_ssm_payload
    nack = generate_ssm_payload(obu_id=OBU_ID, intersection_id=RSU_ID, status=6)
    fake_sk = SigningKey.generate(curve=NIST256p)
    fake_pub = fake_sk.get_verifying_key().to_string()
    fake_cert = {"rsu_id": RSU_ID, "pub": pki._b64(fake_pub), "ca_sig": pki._b64(fake_sk.sign(b"x"))}
    unsigned_ok = obu.ssm_trusted(nack)
    selfsigned_ok = obu.ssm_trusted(pki.sign_ssm(nack, fake_sk, fake_cert))
    return not unsigned_ok and not selfsigned_ok, f"unsigned accepted={unsigned_ok}; self-signed accepted={selfsigned_ok}", True


@case("S2", "forged downlink", "SSM genuinely signed by RSU 2 but claiming intersection 1 (status=4 + prewarm list)",
      "F-6: SSM intersection id must equal the RSU id in its certificate")
def t_s2(legit, sock):
    from RSU.gen_payload import generate_ssm_payload
    sk2, cert2 = rsu._rsu_signer(2)
    ssm = pki.sign_ssm(generate_ssm_payload(obu_id=OBU_ID, intersection_id=1, status=4, prewarmed_rsus=[3, 4]), sk2, cert2)
    ok = obu.ssm_trusted(ssm)
    return not ok, f"cross-intersection SSM accepted={ok}", True


@case("S3", "replay downlink", "replay a genuine status=6 SSM captured more than 1 s earlier",
      "F-6: OBU rejects SSM older than 1 s")
def t_s3(legit, sock):
    from RSU.gen_payload import generate_ssm_payload
    sk, cert = rsu._rsu_signer(RSU_ID)
    ssm = pki.sign_ssm(generate_ssm_payload(obu_id=OBU_ID, intersection_id=RSU_ID, status=6), sk, cert)
    fresh_ok = obu.ssm_trusted(ssm)
    time.sleep(1.1)
    replay_ok = obu.ssm_trusted(ssm)
    return fresh_ok and not replay_ok, f"fresh accepted={fresh_ok}; replay after 1.1s accepted={replay_ok}", True


@case("Q1", "quantum attacker", "ECDSA key of AMB-217 broken (Shor), ML-DSA key unknown; Full packet",
      "Tier-2 ML-DSA-44 verify rejects green (residual: F1 still flashes yellow and FULL_SIG_FAIL blacklists the real vehicle)")
def t_q1(legit, sock):
    msg = srm_bytes()
    _, fake_priv = new_pqc_keypair()
    sig = pqc_sign(fake_priv, msg)
    pkt = assemble(msg, ecc_sign(legit.ecc_sk, msg, sig), legit, sig)
    r = deliver(make_fragments(pkt, next_msg_id()), ATK_ADDR, sock)
    banned = OBU_ID in rsu.blacklist
    return not r["green"], f"flash(yellow)={r['flash']} green={r['green']}; real AMB-217 blacklisted={banned}", True


@case("Q2", "quantum attacker", "ECDSA key of AMB-217 broken, ML-DSA key unknown; Short packet",
      "Tier-2 ML-DSA-44 verify with cached pk rejects")
def t_q2(legit, sock):
    prewarm(legit)
    msg = srm_bytes()
    _, fake_priv = new_pqc_keypair()
    sig = pqc_sign(fake_priv, msg)
    pkt = assemble(msg, ecc_sign(legit.ecc_sk, msg, sig), legit, sig, short=True)
    r = deliver(make_fragments(pkt, next_msg_id()), ATK_ADDR, sock)
    return not r["green"], f"flash(yellow)={r['flash']} green={r['green']} nack={r['nack']}", True


@case("Q3", "quantum attacker", "CA ECC root key broken (Shor on Q_CA); attacker mints ECQV cert for AMB-217 "
      "bound to its own ML-DSA key", "F-5: CA ML-DSA-44 certificate over (ID, role, P_U, H(pk)) in Full packets")
def t_q3(legit, sock):
    with open("CA/keys/ca_ecc_priv.key", "rb") as f:          # 模擬 Shor 演算法自 Q_CA 求得 d_CA
        d_CA = serialization.load_der_private_key(f.read(), password=None).private_numbers().private_value
    forged = forge_ecqv_with_ca_key(OBU_ID, d_CA)
    results = []
    for ca_cert in (b"", legit.ca_cert, os.urandom(2420)):   # 無憑證 / 盜用 AMB-217 的真憑證 / 隨機
        forged.ca_cert = ca_cert
        results.append(deliver(make_fragments(honest_packet(forged), next_msg_id()), ATK_ADDR, sock)["green"])
    return not any(results), f"green with (no cert, stolen legit cert, random cert)={results}", True


@case("Q4", "quantum attacker", "ECDSA key of AMB-217 broken; cache warm; Full packet with attacker's own ML-DSA key "
      "(no CA key needed)", "F-7 cache key + F-5 CA PQC certificate")
def t_q4(legit, sock):
    deliver(make_fragments(honest_packet(legit), next_msg_id()), LEGIT_ADDR, sock)      # 快取已暖
    pub, priv = new_pqc_keypair()
    msg = srm_bytes()
    sig = pqc_sign(priv, msg)
    pkt = assemble(msg, ecc_sign(legit.ecc_sk, msg, sig), legit, sig, pqc_hash=hashlib.sha256(pub).digest(), pqc_pub=pub)
    r = deliver(make_fragments(pkt, next_msg_id()), ATK_ADDR, sock)
    poisoned = parse.query_pqc_pub_cache(legit.id_raw, rsu_id=RSU_ID) == pub
    return not r["green"] and not poisoned, f"green={r['green']}; PQC cache poisoned={poisoned}", True


HEADERS = {"id": "編號", "threat": "威脅類別", "attacker": "攻擊者能力與手法", "mechanism": "防禦機制",
           "expected": "預期結果", "defended": "是否防禦成功", "observed": "實際觀察"}


def main():
    legit = load_legit()
    rows = []
    with contextlib.redirect_stdout(io.StringIO()):
        for t in TESTS:
            reset_rsu()
            sock = CaptureSock()
            try:
                ok, observed, expected_defended = t["fn"](legit, sock)
            except Exception as e:
                ok, observed, expected_defended = False, f"ERROR {type(e).__name__}: {e}", True
            rows.append({"id": t["id"], "threat": t["threat"], "attacker": t["attacker"], "mechanism": t["mechanism"],
                         "expected": "defended" if expected_defended else "vulnerable (known gap)",
                         "defended": "yes" if ok else "NO", "observed": observed})

    os.makedirs("security/results", exist_ok=True)
    with open("security/results/attack_results.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(HEADERS.values())
        for r in rows:
            w.writerow(r[k] for k in HEADERS)
    for r in rows:
        print(f"[{r['id']:<3}] {r['defended']:<3} {r['threat']:<28} {r['observed']}")
    unexpected = [r for r in rows if (r["defended"] == "yes") != (r["expected"] == "defended")]
    print(f"\n{len(rows)} 項測試，防禦成功 {sum(r['defended'] == 'yes' for r in rows)} 項；"
          f"與預期不符 {len(unexpected)} 項：{[r['id'] for r in unexpected]}")


if __name__ == "__main__":
    main()
