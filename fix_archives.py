import os
import re

TARGET_DIR = "docs/_posts"

def normalize_table(content):
    """
    v4.0 修復邏輯：
    1. 移除表格行的縮排 (解決變Code Block的問題)
    2. 確保表格上方有空行
    3. 統一表格分隔線格式
    """
    
    lines = content.split('\n')
    new_lines = []
    in_table = False
    
    for i, line in enumerate(lines):
        stripped = line.strip()
        
        # 偵測是否為表格行 (以 | 開頭和結尾)
        is_table_row = stripped.startswith('|') and stripped.endswith('|')
        
        if is_table_row:
            # 如果這是表格的第一行，且前一行不是空行，插入一個空行
            if not in_table:
                if new_lines and new_lines[-1].strip() != "":
                    new_lines.append("") # 插入空行，斷開清單連結
            
            in_table = True
            
            # 【關鍵修復】: 移除所有縮排，強制頂格
            # 並且順手修復分隔線，把 "| - |" 這種變成 "|---|---|---|---"
            # 簡單判斷：如果這行只有 - | 和 空白，那就是分隔線
            if re.match(r'^\|[\s\-:\|]+$', stripped):
                # 計算欄位數
                cols = stripped.count('|') - 1
                # 重建成標準分隔線
                clean_line = "|" + "---|" * cols
            else:
                clean_line = stripped
            
            new_lines.append(clean_line)
            
        else:
            in_table = False
            new_lines.append(line) # 保持原樣 (包含原本清單的縮排)
            
    return '\n'.join(new_lines)

def main():
    print(f"🔧 [Fixer v4.0] 啟動：移除表格縮排並標準化... ({TARGET_DIR})")
    
    if not os.path.exists(TARGET_DIR):
        print(f"❌ 找不到目錄: {TARGET_DIR}")
        return

    modified_count = 0

    for filename in os.listdir(TARGET_DIR):
        if filename.endswith(".md"):
            filepath = os.path.join(TARGET_DIR, filename)
            
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    original = f.read()
                
                # 執行修復
                fixed = normalize_table(original)
                
                # 只有當內容真的變了才存檔
                if fixed != original:
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(fixed)
                    print(f"✅ 已修復: {filename}")
                    modified_count += 1
                    
            except Exception as e:
                print(f"❌ 失敗 {filename}: {e}")

    print("-" * 30)
    print(f"📊 總計修復檔案數: {modified_count}")
    print("-" * 30)

if __name__ == "__main__":
    main()