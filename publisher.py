
import os
import re
from datetime import datetime

def save_to_jekyll(title, content, category="security", output_dir="docs/_posts"):
    """
    將內容轉換為 Jekyll Markdown，並自動修復常見的 AI 格式錯誤，
    同時注入威脅等級 (severity) 到 Front Matter。
    """
    # 1. 準備時間與檔名
    today = datetime.now()
    date_str = today.strftime("%Y-%m-%d")
    time_str = today.strftime("%Y-%m-%d %H:%M:%S +0000")

    safe_title = title.replace(" ", "-").replace("/", "-").replace(":", "").replace("?", "")
    filename = f"{date_str}-{safe_title}.md"
    filepath = os.path.join(output_dir, filename)

    # ================================================
    # ✨ NEW: 動態威脅等級分析 (v1.0)
    # ================================================
    severity = "info" # 默認為 info
    severity_match = re.search(r"\*\*嚴重等級\*\*:\s*([\u4e00-\u9fa5]+)", content)
    if severity_match:
        level_text = severity_match.group(1).strip()
        level_map = {
            "極高": "critical",
            "嚴重": "critical",
            "高": "high",
            "中": "medium",
            "低": "info"
        }
        severity = level_map.get(level_text, "info")
    
    # ==========================================
    # 🧹 Auto-Formatter (自動排版修復引擎 v4.0)
    # ==========================================

    # 1. 【表格前置修復】確保表格標題列 (|...|) 前面有兩個換行
    content = re.sub(r'([^\n])\n([ \t]*\|)', r'\1\n\n\2', content)

    # 2. 【Code Block 前置修復】確保 ``` 前面有換行
    content = re.sub(r'([^\n])\s*```', r'\1\n\n```', content)

    # 3. 【Code Block 後置修復】確保 ``` 後面有換行
    content = re.sub(r'```([^\n])', r'```\n\n\1', content)

    # 4. 【表格深度修復邏輯】(移植自 Gemini 修復腳本)
    def process_table_block(match):
        table_text = match.group(0)
        lines = table_text.strip().split('\n')
        processed_lines = [line.lstrip() for line in lines]
        if len(processed_lines) > 1:
            header = processed_lines[0]
            num_columns = len([cell for cell in header.split('|') if cell.strip()])
            if num_columns > 0:
                separator = '|' + '---|' * num_columns
                processed_lines[1] = separator
        return '\n'.join(processed_lines)

    table_pattern = r"(?:^[ \t]*\|.*(?:\n|$))+"
    content = re.sub(table_pattern, process_table_block, content, flags=re.MULTILINE)

    # 5. 【智慧縮排 Code Block】(保留)
    def indent_code_block(match):
        list_line = match.group(1)
        code_block = match.group(2)
        indented_block = code_block.replace('\n', '\n    ')
        return f"{list_line}\n\n    {indented_block}"

    content = re.sub(r'([\*\-]\s+.*?:)\s*\n+(```[\s\S]*?```)', indent_code_block, content)

    # 6. 移除多餘的連續空行
    content = re.sub(r'\n{3,}', '\n\n', content)

    # ==========================================

    # 7. 組合內容 (包含新的 severity 欄位)
    full_content = f"""---
layout: post
title:  "{title}"
date:   {time_str}
categories: [{category}]
severity: {severity} # <-- 動態威脅等級
---

{content}
"""

    # 8. 寫入檔案
    try:
        os.makedirs(output_dir, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(full_content)
        print(f"✅ [Publisher] 文章已生成 (Severity: {severity.upper()})：{filename}")
        return filepath
    except Exception as e:
        print(f"❌ [Publisher] 存檔失敗: {e}")
        return None
