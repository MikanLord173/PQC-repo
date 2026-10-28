# 威脅模型與安全性驗證

本文件整理「後量子混合簽章緊急車輛通行系統」的威脅模型，逐一說明每項威脅由哪個機制防禦，並以兩種方法驗證：

- **攻擊模擬**：[`attack_tests.py`](attack_tests.py) 對真實的 CA / OBU / RSU 程式碼發動 26 項攻擊 → [`results/attack_results.csv`](results/attack_results.csv)
- **形式化驗證**：ProVerif 2.05，4 個情境（古典 / 量子攻擊者 × 修正前 / 修正後）→ [`results/proverif_results.csv`](results/proverif_results.csv)（攻擊路徑見 `results/proverif_*.txt`）

> **修正前**：`sim` 分支 commit `86e284f`。首輪驗證找到 6 個缺口（F-1 ~ F-6），實作修正時又發現 F-7。
> **修正後**：本文件所在版本，F-1 ~ F-7 皆已實作；程式碼內以「【安全修正 F-x】」註解標示。

**結果總覽**

| | 修正前 | 修正後 |
|---|---|---|
| 攻擊模擬 | 首輪 21 項中防禦 16 項；修正時新增的 T8、Q4 在修正前的程式上也會失敗 | **26 項全數防禦** |
| ProVerif 古典攻擊者 | 綠燈認證、不被封鎖、授權、SSM 真實性皆 false | 除注入式認證外**全部 true** |
| ProVerif 量子攻擊者 | 綠燈認證、授權皆 false | 綠燈認證、授權 **true**；殘餘風險見第 6 節 |

---

## 1. 範圍與假設

**保護資產**

| 資產 | 說明 |
|---|---|
| 號誌控制權 | 只有合法緊急車輛能讓 RSU 切換緊急綠燈（閃黃燈為預備狀態） |
| 金鑰 | 車輛 ECC 私鑰 d_U、車輛 ML-DSA-44 私鑰、CA ECC / ML-DSA 根私鑰、RSU SSM 簽章私鑰、車輛註冊金鑰 |
| 可用性 | 合法救護車不會被攻擊者擋下、誤封鎖或被迫降級 |

**信任假設**

1. CA 誠實且根私鑰安全。車輛須先在受控環境（監理站 / 原廠）登記於 CA 名冊並取得註冊金鑰（`python3 -m CA.registry`，F-3）。
2. RSU 誠實；RSU 由道路主管機關佈建，SSM 簽章金鑰在受控環境配發（`python3 -m RSU.setup`）；RSU 之間的有線骨幹（金鑰預熱）為受保護網路。
3. 車輛與 RSU 時鐘同步（GNSS），誤差遠小於 150 ms 時效視窗。

**攻擊者模型**

| 代號 | 能力 |
|---|---|
| 古典網路攻擊者 | Dolev-Yao：可竊聽、攔截、竄改、重放、注入任意封包，可偽造來源位址 |
| 內部攻擊者 | 持有一台或多台「已合法註冊的一般車輛」的全部金鑰（含註冊金鑰） |
| 量子攻擊者 | 以 Shor 演算法破解所有 ECC 私鑰（車輛 ECDSA、CA 的 ECQV 根金鑰、RSU 的 SSM 簽章金鑰）；無法破解 ML-DSA-44、SHA-256 與 HMAC-SHA256 |

**不在範圍**：實體竊取 OBU / 註冊金鑰、側通道攻擊、無線電干擾（jamming）。

---

## 2. 修正後的協定

```
註冊 (TCP 0x57)：OBU → CA   ID ‖ R_U ‖ pk_PQC ‖ HMAC(註冊金鑰, ID ‖ R_U ‖ pk_PQC)              ← F-3
                 CA → OBU   P_U ‖ r ‖ role ‖ certPQC ‖ Q_CA(DER)
                 e = H(ID ‖ role ‖ P_U ‖ H(pk_PQC))，role 取自 CA 名冊                            ← F-2
                 certPQC = ML-DSA_CA("PQC-EV-CERT-v1" ‖ ID ‖ role ‖ P_U ‖ H(pk_PQC))              ← F-5

上行 SRM：sig_PQC = ML-DSA(payload)
          sig_ECC = ECDSA(payload ‖ H(sig_PQC))                                                  ← F-1
  F1   ：承諾 ‖ payload ‖ sig_ECC ‖ ID ‖ role ‖ P_U ‖ H(pk_PQC) ‖ H(sig_PQC)
  F2..N：Full = pk_PQC ‖ certPQC ‖ sig_PQC；Short = sig_PQC（省略 1312 B 公鑰與 2420 B 憑證）

下行 SSM：JSON ‖ rsu_cert(rsu_id, pub, ECDSA_CA) ‖ ECDSA_RSU(SSM)                                  ← F-6
```

RSU 驗證順序（[`parse.py`](../RSU/parse.py)）：ECC 簽章與角色 → H(sig_PQC) 比對 → PQC 公鑰雜湊 / CA 後量子憑證（Full）或快取公鑰比對（Short）→ ML-DSA。只有前面全部通過、ML-DSA 仍失敗時，才能把失敗歸責於車輛本身並硬封鎖。

---

## 3. 威脅模型表

結論：✅ 已防禦　⚠️ 部分防禦（殘餘風險見第 6 節）　❌ 未防禦

| # | 類別 | 攻擊手法 | 防禦機制（程式位置） | 測試 | 修正前 | 修正後 |
|---|---|---|---|---|---|---|
| 1 | 偽造 | 無金鑰者以隨機 ECC 金鑰偽造 AMB-217 的 SRM | ECQV 重構 Q_U = e·P_U + Q_CA 後驗 ECDSA（[`parse.py:257`](../RSU/parse.py#L257)） | F1 | ✅ | ✅ |
| 2 | 竄改 | 簽章後修改 SRM 欄位（路口編號） | ECDSA 與 ML-DSA 簽章涵蓋 payload | T1 | ✅ | ✅ |
| 3 | 竄改 | 翻轉 ECDSA 簽章位元 | ECDSA 驗簽 | T2 | ✅ | ✅ |
| 4 | 竄改 | 竄改後續分片中的 ML-DSA 簽章 | F1 SHA-256 分片雜湊承諾 Early-Drop（[`main.py:623`](../RSU/main.py#L623)） | T3 | ✅ | ✅ |
| 5 | 竄改 | 置換 Full 封包的 PQC 公鑰並重算分片承諾 | H(pk_PQC) 綁入 ECQV 糾纏值 e，RSU 比對雜湊（[`parse.py:369`](../RSU/parse.py#L369)） | T4 | ✅ | ✅ |
| 6 | 竄改／嫁禍 | 轉送合法 F1，竄改 ML-DSA 簽章並**重算 F1 分片承諾** | **F-1**：ECC 簽章涵蓋 H(sig_PQC)；竄改落在 `PQC_SIG_HASH_MISMATCH`，只丟棄、不封鎖（[`parse.py:352`](../RSU/parse.py#L352)） | T5 | ❌ 合法車被封鎖 30 s | ✅ |
| 7 | 竄改 | 對合法會話注入偽造 F2 | Early-Drop 雜湊承諾 | T6 | ✅ | ✅ |
| 8 | 竄改 | 搶先送出被污染的 XOR 修復片 | 還原片比對 F1 承諾，污染片只淘汰不刪會話（[`main.py:447`](../RSU/main.py#L447)） | T7 | ✅ | ✅ |
| 9 | 竄改／快取污染 | 快取已暖時，轉送合法 SRM 與 ECC 簽章，換上攻擊者的 pqc_pub_hash、PQC 公鑰與 ML-DSA 簽章 | **F-7**：ECQV 快取鍵涵蓋 (ID, role, P_U, H(pk))（[`parse.py:74`](../RSU/parse.py#L74)）；F-1、F-5 | T8 | ❌ 快取被污染，合法車 Short 失效 | ✅ |
| 10 | 冒充 | 已註冊車用自己的金鑰，宣稱 ID = AMB-217 | ECQV：Q_U 由宣稱的 ID 重構，金鑰不匹配 | I1 | ✅ | ✅ |
| 11 | 冒充 | 已註冊車盜用 AMB-217 的 P_U 與公鑰雜湊 | ECQV 隱式憑證綁定 d_U ↔ (ID, role, P_U, H(pk)) | I2 | ✅ | ✅ |
| 12 | 越權 | **已註冊的一般車**在 SRM 自稱 role = 救護車，或竄改封包的角色欄位 | **F-2**：角色綁入 ECQV 與 CA 憑證，RSU 要求緊急角色且與 SRM 一致（[`parse.py:196`](../RSU/parse.py#L196)） | I3 | ❌ 取得綠燈 | ✅ |
| 13 | 冒充 | 向 CA 冒名申請 ID = AMB-217（或未登記 ID）的憑證 | **F-3**：CA 名冊 + HMAC 驗證註冊請求（[`enroll.py:14`](../CA/enroll.py#L14)、[`listen.py:45`](../CA/listen.py#L45)） | I4 | ❌ CA 發出第二張 AMB-217 憑證 | ✅ |
| 14 | 嫁禍 | 大量送出宣稱 AMB-217 的無效 F1 | 認證前一律只丟棄、不封鎖 | I5 | ✅ | ✅ |
| 15 | 重放 | 150 ms 後重放截獲的訊息 | `full_timestamp` 150 ms 時效（[`parse.py:270`](../RSU/parse.py#L270)） | R1 | ✅ | ✅ |
| 16 | 重放 | 150 ms 內、合法會話進行中，從其他位址重放 | 每車會話以 F1 時間戳去重（[`main.py:559`](../RSU/main.py#L559)） | R2 | ✅ | ✅ |
| 17 | 重放 | 150 ms 內、**合法會話完成後**從其他位址重放 | **F-4**：以 (obu_id, full_timestamp) 記錄已放行的 SRM（[`main.py:282`](../RSU/main.py#L282)、[`main.py:531`](../RSU/main.py#L531)） | R3 | ❌ 重複放行 | ✅ |
| 18 | 偽造下行 | 偽造 SSM（未簽章、或自簽 RSU 憑證）status = 6 迫使車輛退回 Full | **F-6**：OBU 驗證 CA 簽發的 RSU 憑證與 SSM 簽章（[`OBU/main.py:40`](../OBU/main.py#L40)、[`pki.py`](../pki.py)） | S1 | ❌（程式碼審查） | ✅ |
| 19 | 偽造下行 | RSU 2 的合法金鑰簽出宣稱路口 1 的 SSM（status = 4 + 預熱清單） | **F-6**：SSM 路口編號須等於憑證上的 RSU 編號 | S2 | ❌（程式碼審查） | ✅ |
| 20 | 重放下行 | 重放 1 秒前截獲的合法 status = 6 SSM | **F-6**：OBU 拒絕超過 1 秒的 SSM | S3 | ❌（程式碼審查） | ✅ |
| 21 | 量子 | 破解車輛 ECDSA，偽造 Full 封包 | Tier-2 ML-DSA-44 驗簽擋下綠燈；**仍可**偽造閃黃燈並誘發硬封鎖 | Q1 | ⚠️ | ⚠️ 見 6.1 |
| 22 | 量子 | 破解車輛 ECDSA，偽造 Short 封包 | ML-DSA 以快取中的公鑰驗證 | Q2 | ✅ | ✅ |
| 23 | 量子 | 破解 **CA 的 ECC 根金鑰**，自行簽發綁定自己 ML-DSA 公鑰的 AMB-217 憑證 | **F-5**：Full 封包須附 CA ML-DSA-44 憑證（[`parse.py:379`](../RSU/parse.py#L379)） | Q3 | ❌ 兩層驗證皆通過 | ✅ |
| 24 | 量子 | 只破解車輛 ECDSA（不需 CA 金鑰），快取已暖時以**自己的 ML-DSA 金鑰**送 Full 封包 | **F-7** 快取鍵 + **F-5** CA 後量子憑證 | Q4 | ❌ 取得綠燈並污染快取 | ✅ |
| 25 | 阻斷服務 | 大量封包、不完整分片耗盡記憶體 | IP 限流 50 包/秒、每車 F1 限流 10 次/秒、暫存池上限 100、LRU 快取上限（[`main.py:142`](../RSU/main.py#L142)） | T6、I5 | ⚠️ | ⚠️ 偽造來源 IP 可繞過 IP 限流 |
| 26 | 金鑰保密 | 從通訊內容推得私鑰 | 協定只傳公鑰與簽章 | ProVerif | ✅ | ✅ |

---

## 4. 形式化驗證結果（ProVerif）

修正前模型 = commit `86e284f` 的設計（CA 不驗證註冊申請、明文 SSM）；修正後模型 = 本版實作（F-1 ~ F-6）。F-7 是實作層的快取鍵錯誤，不在符號模型的抽象範圍內，由攻擊模擬 T8 / Q4 驗證。

| 性質 | 古典・修正前 | 古典・修正後 | 量子・修正前 | 量子・修正後 |
|---|---|---|---|---|
| 綠燈認證性（RSU 對 idA 放行 ⇒ idA 確實送出該 SRM） | ❌ false | ✅ true | ❌ false | ✅ true |
| 閃黃燈認證性 | ❌ false | ✅ true | ❌ false | ❌ false（本質限制） |
| 注入式認證（每則 SRM 至多放行一次） | ❌ false | ❌ false（見下） | — | — |
| 攻擊者無法讓合法車被封鎖 | ❌ false | ✅ true | ❌ false | ❌ false（殘餘風險 6.1） |
| 只有 CA 註冊的緊急車能觸發綠燈 | ❌ false | ✅ true | ❌ false | ✅ true |
| OBU 接受的 SSM 必為 RSU 所送 | ❌ false | ✅ true | ❌ false | ❌ false（殘餘風險 6.2） |
| 車輛 ML-DSA 私鑰保密 | ✅ true | ✅ true | ✅ true | ✅ true |
| CA 私鑰保密 | ✅ true（ECC） | ✅ true（ECC） | （假設已破解） | ✅ true（ML-DSA） |

**模型抽象**：分片、XOR / DUP、雜湊承諾視為傳輸細節，封包以單一訊息表示；150 ms 時效以 fresh nonce 表示。

**注入式認證**：修正後 RSU 以表格記錄已放行的 (ID, 時間戳)（F-4），但 ProVerif 的 `get … else insert` 不是原子操作，兩個 RSU 程序可能同時查表、各放行一次，所以仍回報 false。實際 RSU 是單執行緒事件迴圈，查表與寫入之間不會交錯，攻擊模擬 R2 / R3 已驗證。

**ProVerif 找到的修正前攻擊路徑**（與攻擊模擬一致）：
- **古典・綠燈**：攻擊者向不驗證身分的 CA 申請 `ecqvSK(skCA, idA, h(ppk(k)), p)`，搭配自己的 ML-DSA 金鑰 `k` 通過兩層驗證（= I4）。
- **古典・封鎖**：取得兩則合法 Full 訊息，把其中一則的 ML-DSA 簽章換成另一則的；ECC 簽章仍有效，ML-DSA 驗簽失敗，RSU 封鎖 idA（= T5）。
- **量子・綠燈**：以破解的 `skCA` 為 idA 自行計算 ECQV 私鑰，搭配自己的 ML-DSA 金鑰（= Q3）。

---

## 5. 發現與修正

| 編號 | 嚴重度 | 問題 | 修正（已實作） | 驗證 |
|---|---|---|---|---|
| **F-5** | 高 | 量子攻擊者破解 CA ECC 根金鑰後，可冒充任何車輛通過兩層驗證。混合設計的後量子層，信任錨卻是 ECC。commit `75f87c3` 為了省 2.4 KB 移除了原有的 CA ML-DSA 簽章 | CA 以 ML-DSA-44 根金鑰簽署 `(ID ‖ role ‖ P_U ‖ H(pk_PQC))`，Full 封包夾帶，RSU 驗證後才寫入快取；Short 沿用快取（[`CA/enroll.py`](../CA/enroll.py)、[`parse.py:379`](../RSU/parse.py#L379)） | Q3、Q4；ProVerif 量子・修正後 |
| **F-1** | 高 | ECC 簽章不涵蓋 PQC 簽章，中間人可讓合法救護車被硬封鎖 30 秒（不需量子） | ECC 簽署 `payload ‖ H(sig_PQC)`，H(sig_PQC) 以 32 B 放在 F1；RSU 先比對雜湊，不符只丟棄（[`encode_packet.py`](../OBU/encode_packet.py)、[`parse.py:352`](../RSU/parse.py#L352)） | T5；ProVerif 古典・修正後 |
| **F-7** | 高 | RSU 的 ECQV 公鑰快取以 (ID, P_U) 為鍵，不含 pqc_pub_hash：快取命中時，宣稱不同 PQC 公鑰的封包仍用舊 Q_U 驗 ECC。中間人可污染 PQC 公鑰快取；量子攻擊者只需破解車輛自己的 ECDSA 就能取得綠燈 | 快取鍵改為 (ID, role, P_U, H(pk_PQC))；Short 模式另檢查快取公鑰的雜湊等於封包的 pqc_pub_hash（[`parse.py:74`](../RSU/parse.py#L74)、[`parse.py:362`](../RSU/parse.py#L362)） | T8、Q4（修正時新發現） |
| **F-2** | 高 | 憑證不含角色，任何已註冊車輛都能自稱救護車取得綠燈 | 角色由 CA 名冊決定，綁入 ECQV 糾纏值 e 與 CA 後量子憑證；RSU 要求角色 ∈ {6, 12, 13, 14} 且等於 SRM 宣稱的 role（[`parse.py:196`](../RSU/parse.py#L196)） | I3；ProVerif 古典・修正後 |
| **F-3** | 高 | CA 註冊不驗證申請者，可冒名註冊任何 ID | 車輛須登記於 CA 名冊（`CA/registry.json`），註冊請求附 HMAC-SHA256(註冊金鑰, ID ‖ R_U ‖ pk_PQC)（[`CA/registry.py`](../CA/registry.py)、[`enroll.py:14`](../CA/enroll.py#L14)） | I4；ProVerif 古典・修正後 |
| **F-6** | 中 | 下行 SSM 未簽章：可偽造 status = 6 迫使車輛退回 Full，或偽造預熱清單讓車輛在下游誤用 Short | 每個 RSU 持有 CA 簽發的 ECDSA 金鑰，SSM 夾帶 RSU 憑證與簽章；OBU 驗證憑證、簽章、路口編號與 1 秒時效（[`pki.py`](../pki.py)、[`main.py:243`](../RSU/main.py#L243)、[`OBU/main.py:40`](../OBU/main.py#L40)） | S1 ~ S3；ProVerif 古典・修正後 |
| **F-4** | 低 | 150 ms 內換來源位址重放，已完成的請求會被重複放行 | 以 `(obu_id, full_timestamp)` 記錄 2 秒內已放行的 SRM，F1 與重組完成時都檢查（[`main.py:282`](../RSU/main.py#L282)） | R3 |

**附帶修正**：`OBU.setup` 原本在 CA 核發前就把新的 ML-DSA 金鑰寫入磁碟；註冊失敗時會留下與舊憑證不符的金鑰，之後每個 Full 封包都 `FULL_SIG_FAIL` 而被硬封鎖。改為核發成功後才寫入。

### 5.1 修正的代價

| 項目 | 修正前 | 修正後 | 原因 |
|---|---|---|---|
| Full 封包 | 約 4246 B，4 片 | 約 6696 B，5 片 | +2420 B CA 後量子憑證（F-5）、+33 B role 與 H(sig_PQC) |
| Short 封包 | 約 2934 B，3 片 | 約 2964 B，3 片 | +33 B |
| XOR 模式 F1 | 約 608 B | Full 約 706 B / Short 約 610 B | 新欄位與多 2 片的雜湊承諾；`fec.F1_MAX_XOR_UDP` 由 650 B 調為 720 B |
| 下行 SSM（含預熱清單） | 約 290 B | 約 600 B | RSU 憑證與簽章（F-6） |
| RSU 完整驗證 Full / Short | 2.11 / 2.07 ms | 2.10 / 2.05 ms | 多驗一次 CA ML-DSA 憑證，但 liboqs 0.16 的 ML-DSA 驗證較快，兩者抵銷 |
| RSU 整則訊息到送出 SSM（Full 冷快取 / Short 預熱） | 6.01 / 4.19 ms | 6.52 / 4.65 ms | 主要是 SSM 簽章（約 0.5 ms） |
| mid 掉包環境 Full 一次成功率（none / dup / xor） | 20.2 / 30.7 / 42.8 % | 9.3 / 10.5 / 24.2 % | 封包變大、多一片 |
| mid 掉包環境 Full 平均綠燈觸發時間（none / dup / xor） | 3.10 / 2.24 / 1.39 s | 5.15 / 4.34 / 2.57 s | 同上 |
| mid 掉包環境 Short 一次成功率（none / dup / xor） | 32.8 / 46.2 / 55.1 % | 32.7 / 45.9 / 54.0 % | Short 幾乎不變 |

耗時：修正前 `sim/results/2_old`（liboqs 0.14），修正後 `sim/results/2`（liboqs 0.16），皆 1000 次。行車模擬：修正前 `sim/results/1_old`、`3_old`，修正後 `sim/results/1`、`3`，皆 1000 趟、種子 42，運算耗時常數不變，差異只來自封包格式。模擬沒有計入 RSU 簽 SSM 的約 0.5 ms。

F-5 的代價集中在**首次建聯的 Full 封包**；建聯後的 Short 封包、以及經有線骨幹預熱的下游路口都不受影響，這也讓 Short 模式的節省效果更明顯。

---

## 6. 殘餘風險

### 6.1 量子攻擊者偽造閃黃燈、誘發硬封鎖（Q1）
F1 閃黃燈只驗 ECC，量子攻擊者可以偽造。閃黃燈只能當「預備」訊號，切換綠燈一定要等 ML-DSA 驗證完成（現行設計已是如此）。

`FULL_SIG_FAIL → 30 秒硬封鎖` 的歸責前提是「只有車輛本人能產生有效的 ECC 簽章」。ECC 被破解後這個前提不成立，量子攻擊者可以用偽造的 ECC 簽章搭配無效的 ML-DSA 簽章，讓合法救護車被封鎖（ProVerif 量子・修正後：不被封鎖 = false；攻擊模擬 Q1：`real AMB-217 blacklisted=True`）。可選的處理方式：
- 拿掉 `FULL_SIG_FAIL` 的硬封鎖，只丟棄並交給每車 F1 限流；
- 或保留封鎖，但改成累積多次才封鎖、縮短封鎖時間。

本版保留原本的封鎖機制，此項留給組員決定。

### 6.2 量子攻擊者偽造 SSM
F-6 以 ECDSA 簽 SSM，量子攻擊者可以偽造。影響是迫使車輛退回 Full（多耗頻寬）或在下游誤用 Short（會收到 status = 6 後回復），**不會讓號誌誤放行**。若要抗量子，可改用 ML-DSA 簽 SSM，代價是每則 SSM 多約 2.4 KB 簽章，再加上 RSU 的後量子憑證。

### 6.3 其他
- 偽造來源 IP 可繞過 IP 限流（需由下層網路或 802.11p 的 MAC 層處理）。
- 註冊金鑰以明文存在 `CA/registry.json` 與 `OBU/keys/`（皆已列入 .gitignore）；實務上應放在 HSM / 安全元件。
- RSU 的 SSM 簽章金鑰由 `RSU.setup` 直接呼叫本地 CA 簽發，模擬受控環境佈建，沒有走網路申請流程。

---

## 7. 如何重現

```bash
# 一次性設定 (專案根目錄)
python3 -m CA.gen_keys                      # 只在沒有 CA 金鑰時執行
python3 -m CA.registry AMB-217 --role 14    # 登記救護車，配發註冊金鑰
python3 -m CA.listen &                      # 啟動 CA
python3 -m OBU.setup AMB-217                # 以註冊金鑰申請 ECQV + CA 後量子憑證
python3 -m RSU.setup                        # 取得 CA 公鑰，配發 RSU 1~4 的 SSM 簽章金鑰

# 攻擊模擬
python3 -m security.attack_tests

# ProVerif（需安裝 ProVerif 2.05+，或以環境變數 PROVERIF 指定路徑）
python3 -m security.proverif.run_proverif
```

---

## 8. 後續：Veins 車聯網模擬規劃

目標：比較「無認證」與「有認證」時，惡意車廣播假緊急煞車訊息對車流的影響。

- **場景**：SUMO 單向多車道道路，車流密度可調；一台惡意車週期性廣播假的緊急煞車警示（EEBL / DENM 類訊息）。
- **兩種接收端**：
  - 無認證：收到即依訊息減速。
  - 有認證：以本系統的混合簽章驗證，攻擊者沒有合法金鑰，訊息被丟棄。驗證時間使用第 2 組實驗量到的數值（例如 F1 驗證約 4 ms、完整驗證約 2.6 ms）作為處理延遲。
- **比較指標**：平均車速、旅行時間、急煞次數、最小車距／TTC、道路吞吐量。
- **注意**：現行系統的訊息是 SRM / SSM，緊急煞車需要新增訊息類型，並沿用相同的簽章格式。
