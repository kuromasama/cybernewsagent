import os
import re
from datetime import datetime

def save_to_jekyll(title, content, category="security", output_dir="docs/_posts"):
    """
    將內容轉換為 Jekyll Markdown，並自動修復常見的 AI 格式錯誤
    """
    # 1. 準備時間與檔名
    today = datetime.now()
    date_str = today.strftime("%Y-%m-%d")
    time_str = today.strftime("%Y-%m-%d %H:%M:%S +0000") 
    
    safe_title = title.replace(" ", "-").replace("/", "-").replace(":", "").replace("?", "")
    filename = f"{date_str}-{safe_title}.md"
    filepath = os.path.join(output_dir, filename)
    
    # ==========================================
    # 🧹 Auto-Formatter (自動排版修復引擎 v4.0)
    # ==========================================
    
    # 1. 【表格前置修復】確保表格標題列 (|...|) 前面有兩個換行
    # 這會把 "IOCs:\n| Hash |" 變成 "IOCs:\n\n| Hash |"
    content = re.sub(r'([^\n])\n([ \t]*\|)', r'\1\n\n\2', content)

    # 2. 【Code Block 前置修復】確保 ``` 前面有換行
    content = re.sub(r'([^\n])\s*```', r'\1\n\n```', content)

    # 3. 【Code Block 後置修復】確保 ``` 後面有換行
    content = re.sub(r'```([^\n])', r'```\n\n\1', content)

    # 4. 【表格深度修復邏輯】(移植自 Gemini 修復腳本)
    # 目的：移除表格縮排、修復分隔線
    
    def process_table_block(match):
        table_text = match.group(0)
        lines = table_text.strip().split('\n')
        
        # (A) 移除每一行的縮排 (關鍵！避免變成 Code Block)
        processed_lines = [line.lstrip() for line in lines]
        
        # (B) 重建標準分隔線 (|---|---|)
        if len(processed_lines) > 1:
            header = processed_lines[0]
            # 計算有幾個欄位
            num_columns = len([cell for cell in header.split('|') if cell.strip()])
            
            if num_columns > 0:
                # 建立標準 Markdown 分隔線
                separator = '|' + '---|' * num_columns
                processed_lines[1] = separator
                
        return '\n'.join(processed_lines)

    # Regex: 抓取連續的表格行 (允許縮排)
    table_pattern = r"(?:^[ \t]*\|.*(?:\n|$))+"
    content = re.sub(table_pattern, process_table_block, content, flags=re.MULTILINE)

    # 5. 【智慧縮排 Code Block】(保留此功能)
    # 讓清單內的 Code Block 縮排，但表格絕對不能縮排
    def indent_code_block(match):
        list_line = match.group(1)
        code_block = match.group(2)
        indented_block = code_block.replace('\n', '\n    ')
        return f"{list_line}\n\n    {indented_block}"

    # 偵測模式： (清單行) + (換行) + (程式碼區塊)
    content = re.sub(r'([\*\-]\s+.*?:)\s*\n+(```[\s\S]*?```)', indent_code_block, content)
    
    # 6. 移除多餘的連續空行
    content = re.sub(r'\n{3,}', '\n\n', content)

    # ==========================================

    # 7. 插入被動收入 (暫時關閉)
    affiliate_block = ""
    # if category == "security":
    #     affiliate_block = """
    #     \n
    #     ---
    #     ### 🔒 資安專家推薦
    #     * **NordVPN**：保護您的網路足跡，防止駭客追蹤。[👉 點此查看優惠](您的連結)
    #     * **Ledger 冷錢包**：保護加密資產的最佳實體錢包。[👉 了解更多](您的連結)
    #     ---
    #     """
    
    # 8. 組合內容
    full_content = f"""---
layout: post
title:  "{title}"
date:   {time_str}
categories: [{category}]
---

{content}

{affiliate_block}
"""

    # 9. 寫入檔案
    try:
        os.makedirs(output_dir, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(full_content)
        print(f"✅ [Publisher] 文章已生成並自動排版：{filename}")
        return filepath
    except Exception as e:
        print(f"❌ [Publisher] 存檔失敗: {e}")
        return None