import os
import re

#設定目標資料夾 (根據您的截圖)
TARGET_DIR = "docs/_posts"

def auto_format_content(content):
    """
    核心排版修復邏輯 (與 publisher.py 同步)
    """
    
    # 1. 修復表格：只要看到 "|" 開頭的行，且前面不是空行，就強制加兩個換行
    # 這會把 "IOCs:\n| Hash |" 變成 "IOCs:\n\n| Hash |"
    content = re.sub(r'([^\n])\n(\|.*\|)', r'\1\n\n\2', content)
    
    # 2. 修復 Code Block 前端：確保 ``` 前面有換行
    content = re.sub(r'([^\n])```', r'\1\n\n```', content)
    
    # 3. 修復 Code Block 後端：確保 ``` 後面有換行
    content = re.sub(r'```([^\n])', r'```\n\n\1', content)
    
    # 4. 【智慧縮排】(進階功能)
    # 解決清單中的程式碼區塊導致斷行的問題
    def indent_code_block(match):
        list_line = match.group(1)
        code_block = match.group(2)
        # 幫每一行程式碼加縮排 (4個空白)
        indented_block = code_block.replace('\n', '\n    ')
        return f"{list_line}\n\n    {indented_block}"

    # 偵測模式： (清單行) + (換行) + (程式碼區塊)
    content = re.sub(r'([\*\-]\s+.*?:)\s*\n+(```[\s\S]*?```)', indent_code_block, content)
    
    # 5. 移除多餘的連續空行 (超過3行的空行縮減為2行)
    content = re.sub(r'\n{3,}', '\n\n', content)
    
    return content

def main():
    print(f"🔧 [System] 開始掃描目錄: {TARGET_DIR} ...")
    
    if not os.path.exists(TARGET_DIR):
        print(f"❌ [Error] 找不到目錄: {TARGET_DIR}")
        return

    count = 0
    modified_count = 0

    # 遍歷目錄下的所有檔案
    for filename in os.listdir(TARGET_DIR):
        if filename.endswith(".md"):
            filepath = os.path.join(TARGET_DIR, filename)
            count += 1
            
            try:
                # 讀取檔案
                with open(filepath, "r", encoding="utf-8") as f:
                    original_content = f.read()
                
                # 執行修復
                new_content = auto_format_content(original_content)
                
                # 只有當內容真的有變動時才寫入，減少硬碟讀寫
                if new_content != original_content:
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(new_content)
                    print(f"✅ 已修復: {filename}")
                    modified_count += 1
                else:
                    # print(f"💤 無需修復: {filename}")
                    pass
                    
            except Exception as e:
                print(f"❌ 處理失敗 {filename}: {e}")

    print("-" * 30)
    print(f"📊 掃描完成。")
    print(f"   - 總檔案數: {count}")
    print(f"   - 實際修復: {modified_count}")
    print("-" * 30)

if __name__ == "__main__":
    main()