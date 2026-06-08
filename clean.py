import argparse
from pathlib import Path

def clean(targets: list):
    for t in targets:
        # 1. 設定目標資料夾路徑與要刪除的副檔名
        target_dir = Path(f"./{t}")  # 請替換成你的資料夾路徑
        extensions_to_delete = {".bin", ".key"}      # 請替換成你想刪除的副檔名（記得帶點 .）

        # 2. 確保資料夾存在
        if target_dir.exists() and target_dir.is_dir():
            # 如果想包含子資料夾，請把 .iterdir() 改成 .rglob("*")
            for file_path in target_dir.rglob("*"):
                # file_path.suffix 可以取得該檔案的副檔名（例如 ".txt"）
                # .lower() 可以防止因為大小寫不同（如 .TXT）而漏掉
                if file_path.is_file() and file_path.suffix.lower() in extensions_to_delete:
                    try:
                        file_path.unlink()
                        print(f"已成功刪除: {file_path.name}")
                    except Exception as e:
                        print(f"刪除 {file_path.name} 時發生錯誤: {e}")
        else:
            print("找不到指定的資料夾。")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target", type=str, help="清除目標")
    args = parser.parse_args()
    
    target = args.target.upper()

    if target == "ALL":
        clean(["OBU", "RSU", "CA"])
    elif target in ["OBU", "RSU", "CA"]:
        clean([target])
    else:
        print("請指定清除目標")