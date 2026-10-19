# PQC-repo (大專生研究計畫)
後量子密碼學 (ML-DSA-44) 與傳統 ECC (SECP256R1) 混合雙簽章於車聯網 (V2X / VANET) 緊急車輛優先通行機制之實作。

---

# 執行說明
終端機路徑請設在專案根目錄。<br>
若要執行模組，請使用 `python3 -m <模組名稱>`，例如：
```bash
python3 -m OBU.main
```

---

# 執行流程

## 1. 環境設定
在專案根目錄建立 `.env` 檔案（若無則使用預設值）：
```env
CA_IP="127.0.0.1"
CA_PORT=57217
RSU_IP="127.0.0.1"
RSU_PORT=5005
```

## 2. CA 伺服器端
1. 產生 CA 根金鑰對（放入 `CA/keys/`）：
   ```bash
   python3 -m CA.gen_keys
   ```
2. 啟動 CA 伺服器監聽：
   ```bash
   python3 -m CA.listen
   ```

## 3. RSU 路側單元端
1. 向 CA 索取並配置根公鑰（自動存入 `RSU/keys/`）：
   ```bash
   python3 -m RSU.setup
   ```
2. 啟動 RSU 接收端（監聽 5005 埠）：
   ```bash
   python3 -m RSU.main
   ```
3. 按 `Ctrl+C` 可終止程式。

## 4. OBU 緊急車輛端
1. 向 CA 請求憑證並初始化金鑰（命令列參數指定車輛 ID，預設 `AMB-217`）：
   ```bash
   python3 -m OBU.setup AMB-217
   ```
2. 向 RSU 持續發送優先通行封包（指定車輛 ID 與發送頻率，例如每 3 秒發送一次）：
   ```bash
   python3 -m OBU.main AMB-217 3
   ```
3. 按 `Ctrl+C` 可終止程式。

---

# 系統特色與進度

### 已完成項目
- [x] CA 與各節點間之金鑰初始化與憑證發放機制
- [x] 輕量化身分驗證與雙簽章機制
- [x] 兩段式號誌通行預熱與放行機制
- [x] 分片傳輸與抗丟包自癒機制
- [x] 快取機制與安全防護
- [x] 通訊協定標準化封裝

### 進行中 / 下一步目標
- [ ] 模擬環境搭建與效能測試評估
