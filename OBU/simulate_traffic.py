import subprocess
import time
import sys
import random

def run_obu_simulation(num_cars):
    processes = []
    
    print(f"開始模擬 {num_cars} 台緊急車輛同時發送 BSM 封包...")
    print("--------------------------------------------------")

    # 1. 同時啟動多個 OBU 實例
    for i in range(1, num_cars + 1):
        # 產生車輛 ID，例如: EV-001, EV-002...
        obu_id = f"AMB-{i:03d}" 
        freq = random.randrange(1, 20) / 10
        
        print(f"[系統] 正在喚醒車輛 {obu_id} 並發送封包（頻率: {freq}）...")
        
        # 使用 sys.executable 確保使用與目前相同的 Python 環境
        # 執行指令等同於：python OBU/obu_main.py EV-001
        p = subprocess.Popen(
            [
                sys.executable,         # 這是 python 執行檔路徑
                "-m",
                "OBU.main",              # 腳本路徑 (Argument 0)
                obu_id,                 # 車輛編號 (Argument 1)
                "--freq", str(freq)     # 發送頻率 (Argument 2, 3)
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        processes.append((obu_id, p))

    print("--------------------------------------------------")
    print(f"⏳ 所有 {num_cars} 台車已全數出發，正在等待 RSU 處理與回應...")

    # 2. 等待所有進程執行完畢，並收集結果
    success_count = 0
    for obu_id, p in processes:
        try:
            # 設定每個進程最多執行 10 秒，避免某些車卡死導致腳本停住
            stdout, stderr = p.communicate(timeout=10) 
            
            if p.returncode == 0:
                success_count += 1
                # 如果你想看每台車自己印了什麼，可以解開這行：
                # print(f"  > {obu_id} 輸出:\n{stdout.strip()}")
            else:
                print(f"❌ {obu_id} 執行失敗！錯誤訊息：\n{stderr}")
                
        except subprocess.TimeoutExpired:
            print(f"🚨 {obu_id} 回應超時！")
            p.kill()

    print("--------------------------------------------------")
    print(f"📊 測試結束！成功完成發送與驗證的車輛：{success_count}/{num_cars}")

if __name__ == "__main__":
    # 在這裡指定你一次要測試幾台車
    # 建議先從 3~5 台開始測試，沒問題再挑戰 20~50 台
    NUMBER_OF_CARS = 5 
    
    start_time = time.time()
    run_obu_simulation(NUMBER_OF_CARS)
    print(f"⏱️ 總測試自動化耗時：{time.time() - start_time:.2f} 秒")