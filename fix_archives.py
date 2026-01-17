import os
import re

# 設定目標資料夾
TARGET_DIR = "docs/_posts"

def auto_format_content(content):
    """
    Auto-Formatter v3.5: 專門修復表格與清單縮排問題
    """
    
    # -------------------------------------------------------
    # 1. 基礎防護：強制把跟在文字後面的表格切開 (加空行)
    # -------------------------------------------------------
    # 狀況: "文字\n| 表格 |" -> "文字\n\n| 表格 |"
    # 使用 multiline 模式，針對 | 開頭且前面不是空行的狀況
    content = re.sub(r'([^\n])\n(\|.*\|)', r'\1\n\n\2', content)

    # -------------------------------------------------------
    # 2. 進階修復：處理「清單內的表格」(最常見的錯誤原因)
    # -------------------------------------------------------
    # 狀況: 
    # * IOCs:
    # | Hash | Value |
    #
    # 修復後:
    # * IOCs:
    #
    #     | Hash | Value | (加上縮排)
    
    def indent_table_in_list(match):
        list_line = match.group(1)   # 抓取清單行，如 "* IOCs:"
        table_block = match.group(2) # 抓取整個表格區塊
        
        # 幫表格的每一行加上 4 個空白的縮排
        indented_table = ""
        for line in table_block.split('\n'):
            if line.strip() != "":
                indented_table += "    " + line + "\n"
            else:
                indented_table += "\n"
                
        return f"{list_line}\n\n{indented_table}"

    # Regex 解釋：
    # 1. ([\*\-].*?:)  -> 抓取以 * 或 - 開頭，並以 : 結尾的清單行 (例如 "* IOCs:")
    # 2. \s*\n+        -> 中間可能有的空白或換行
    # 3. (\|[\s\S]*?\|) -> 抓取表格區塊 (從第一個 | 到最後一個 |)
    # 4. (?=\n\s*[^\s\|]|$) -> 確保表格結束 (遇到非 | 開頭的新行，或檔案結束)
    pattern = r'(^[\s]*[\*\-].*?:)\s*\n+((?:[\s]*\|.*\|\n?)+)'
    
    content = re.sub(pattern, indent_table_in_list, content, flags=re.MULTILINE)

    # -------------------------------------------------------
    # 3. Code Block 修復 (確保程式碼區塊也有空行)
    # -------------------------------------------------------
    content = re.sub(r'([^\n])\n```', r'\1\n\n```', content)
    content = re.sub(r'```([^\n])', r'```\n\n\1', content)
    
    # 4. 移除過多的空行
    content = re.sub(r'\n{4,}', '\n\n', content)
    
    return content

def main():
    print(f"🔧 [Fixer v3.5] 開始掃描與修復表格縮排: {TARGET_DIR} ...")
    
    if not os.path.exists(TARGET_DIR):
        print(f"❌ [Error] 找不到目錄: {TARGET_DIR}")
        return

    modified_count = 0

    for filename in os.listdir(TARGET_DIR):
        if filename.endswith(".md"):
            filepath = os.path.join(TARGET_DIR, filename)
            
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    original = f.read()
                
                fixed = auto_format_content(original)
                
                if fixed != original:
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(fixed)
                    print(f"✅ 已修復格式: {filename}")
                    modified_count += 1
                    
            except Exception as e:
                print(f"❌ 讀寫失敗 {filename}: {e}")

    print("-" * 30)
    print(f"📊 總計修復檔案數: {modified_count}")
    print("-" * 30)

if __name__ == "__main__":
    main()