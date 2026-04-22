# 執行
終端機路徑請設在 PQC-repo。<br>
若要執行 OBU/main.py，請輸入：<br>
```python -m OBU.main```<br>
以此類推。<br>

# 流程

## OBU端
1. 執行 CA.gen_keys，產生CA金鑰對，或是透過其他裝置取得金鑰對，放入 CA/keys。
2. 執行 OBU.setup，產生OBU金鑰對，並向CA請求憑證。
3. 設定 OBU.main 中的 OBU_ID, RSU_IP, RSU_PORT 及 FREQUENCY。
4. 執行 OBU.main，向 RSU 持續發送封包。
5. 輸入 Ctrl+C 可終止程式。

## RSU端
1. 將CA的兩種公鑰放入 RSU/keys。
2. 執行 RSU.main，接收封包切片。
3. 設定 RSU.main 中的 RSU_IP, RSU_PORT。
3. 輸入 Ctrl+C 可終止程式。

# 注意事項
* OBU.signature 目前沒用到，請無視。
* 目前OBU跟CA必須放在同一台裝置。
* RSU端則要確保自己擁有的CA公鑰跟用來簽署OBU憑證使用的私鑰是同時產生的。
* 可行的解決辦法像是在OBU端產生CA金鑰對並生成憑證，然後把OBU端產生的CA公鑰複製到RSU端的 CA/keys。
* 若有多台OBU端，則要將同一組CA金鑰對複製到所有OBU端的 CA/keys 中。

# 短期目標
* 讓CA產生OBU憑證的過程能夠遠端完成，不必綁在同一裝置。
    * CA可以安放在RSU端，或是其他第三方裝置。
* OBU連線到一RSU時，記錄其IP, PORT。並且RSU端會將該OBU的公鑰存在本機。<br>
若OBU向已記錄的RSU發送封包，省略自己的公鑰，並將OBU公鑰長度的欄位都設為0。<br>
當RSU發現該欄位皆為0，便會嘗試讀取存在本機的OBU公鑰。<br>
每當OBU執行OBU.setup產生新金鑰時，清除RSU的記錄。
* 測試階段先用易讀的PEM格式儲存ECC金鑰對，後期再改成體積小的DER格式。