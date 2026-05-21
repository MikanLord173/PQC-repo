# 執行
終端機路徑請設在 PQC-repo。<br>
若要執行 OBU/main.py，請輸入：<br>
```python -m OBU.main```<br>
以此類推。<br>

# 流程

## 初始化階段
1. 在專案根目錄 (PQC-repo/) 建立名為 ".env" 的檔案
2. 在 .env 設定參數：CA_IP, CA_PORT, RSU_IP, RSU_PORT
3. CA端執行 CA.listen，監聽來自 OBU 與 RSU 的請求。
4. RSU端設定好CA_IP後執行 RSU.setup，請求CA公鑰。
5. OBU端設定好CA_IP後執行 OBU.setup，請求憑證並產生金鑰對。

### .env 檔範例：
```
CA_IP = "127.0.0.1"
CA_PORT = 57217
RSU_IP = "192.168.1.174" 
RSU_PORT = 5005
```

## OBU端執行階段
1. 執行 OBU.main，命令列參數輸入車輛ID(必填)及發送頻率(可選，預設5秒)，向 RSU 持續發送封包。
2. 輸入 Ctrl+C 可終止程式。

## RSU端執行階段
1. 執行 RSU.main，接收封包切片。
2. 輸入 Ctrl+C 可終止程式。

# 注意事項
* OBU.signature 目前沒用到，請無視。

# 短期目標
* 讓CA產生OBU憑證的過程能夠遠端完成，不必綁在同一裝置。
    * CA可以安放在RSU端，或是其他第三方裝置。
* 實裝文獻功能
* 測試遠端發送及多裝置同時發送分片
* 導入 asyncio 進行平行處理
* 日誌生成功能 / 視覺儀表板
* ~~OBU連線到一RSU時，記錄其IP, PORT。並且RSU端會將該OBU的公鑰存在本機。~~<br>
~~若OBU向已記錄的RSU發送封包，省略自己的公鑰，並將OBU公鑰長度的欄位都設為0。~~<br>
~~當RSU發現該欄位皆為0，便會嘗試讀取存在本機的OBU公鑰。~~<br>
~~每當OBU執行OBU.setup產生新金鑰時，清除RSU的記錄。~~<br>