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
    # 🧹 Auto-Formatter (自動排版修復引擎)
    # ==========================================
    
    # 1. 【表格修復】確保表格標題列 (|...|) 前面有兩個換行
    # 說明：Jekyll 規定表格前必須有空行，否則會變亂碼
    content = re.sub(r'([^\n])\n(\|.*\|.*\|)', r'\1\n\n\2', content)

    # 2. 【Code Block 前置修復】確保 ``` 前面有換行
    # 避免文字跟程式碼黏在同一行
    content = re.sub(r'([^\n])\s*```', r'\1\n\n```', content)

    # 3. 【Code Block 後置修復】確保 ``` 後面有換行
    content = re.sub(r'```([^\n])', r'```\n\n\1', content)

    # 4. 【智慧縮排】(進階)
    # 如果上一行是清單項目 (如 "* 說明:" 或 "1. 步驟:")，且下一行是 Code Block
    # 強制幫 Code Block 加上 4 個空白的縮排，讓它乖乖待在清單裡
    def indent_code_block(match):
        list_line = match.group(1)
        code_block = match.group(2)
        # 幫每一行程式碼加縮排
        indented_block = code_block.replace('\n', '\n    ')
        return f"{list_line}\n\n    {indented_block}"

    # 偵測模式： (清單行) + (換行) + (程式碼區塊)
    content = re.sub(r'([\*\-]\s+.*?:)\s*\n+(```[\s\S]*?```)', indent_code_block, content)

    # ==========================================

    # 5. 插入被動收入 (暫時關閉)
    affiliate_block = ""
    # if category == "security":
    #     affiliate_block = """..."""
    
    # 6. 組合內容
    full_content = f"""---
layout: post
title:  "{title}"
date:   {time_str}
categories: [{category}]
---

{content}

{affiliate_block}
"""

    # 7. 寫入檔案
    try:
        os.makedirs(output_dir, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(full_content)
        print(f"✅ [Publisher] 文章已生成並自動排版：{filename}")
        return filepath
    except Exception as e:
        print(f"❌ [Publisher] 存檔失敗: {e}")
        return None
