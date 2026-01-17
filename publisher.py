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
    # ✨ NEW: 動態威脅等級分析 (v1.0 Fix)
    # ================================================
    severity = "info" # 默認為 info
    
    # 搜尋中文等級 (確保 Regex 是連續的字串)
    severity_match = re.search(r'\*\*嚴重等級\*\*:\s*([\u4e00-\u9fa5]+)', content)
    
    # 如果找不到中文，嘗試找英文 (Critical/High...)
    if not severity_match:
        severity_match = re.search(r'\*\*Severity\*\*:\s*([a-zA-Z]+)', content, re.IGNORECASE)

    if severity_match:
        level_text = severity_match.group(1).strip().lower()
        level_map = {
            "極高": "critical", "critical": "critical",
            "嚴重": "critical",
            "高": "high", "high": "high",
            "中": "medium", "medium": "medium",
            "低": "info", "low": "info", "info": "info"
        }
        severity = level_map.get(level_text, "info")
    
    print(f"   🔍 分析威脅等級: {level_text if severity_match else '未偵測'} -> {severity.upper()}")

    # ==========================================
    # 🧹 Auto-Formatter (自動排版修復引擎 v4.1)
    # ==========================================
    
    # 1. 【表格前置修復】確保表格標題列 (|...|) 前面有兩個換行
    # 修復了上一版 Regex 被換行切斷的問題
    content = re.sub(r'([^\n])\n([ \t]*\|)', r'\1\n\n\2', content)
    
    # 2. 【Code Block 前置修復】確保 ``` 前面有換行
    content = re.sub(r'([^\n])\s*```', r'\1\n\n```', content)

    # 3. 【Code Block 後置修復】確保 ``` 後面有換行
    content = re.sub(r'```([^\n])', r'```\n\n\1', content)
    
    # 4. 【表格深度修復邏輯】(移植自 Gemini 修復腳本)
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

    # Regex: 抓取連續的表格行 (修正了斷行問題)
    table_pattern = r"(?:^[ \t]*\|.*(?:\n|$))+"
    content = re.sub(table_pattern, process_table_block, content, flags=re.MULTILINE)

    # 5. 【智慧縮排 Code Block】(保留)
    def indent_code_block(match):
        list_line = match.group(1)
        code_block = match.group(2)
        indented_block = code_block.replace('\n', '\n    ')
        return f"{list_line}\n\n    {indented_block}"

    # 修正 Regex 斷行
    content = re.sub(r'([\*\-]\s+.*?:)\s*\n+(```[\s\S]*?```)', indent_code_block, content)
    
    # 6. 移除多餘的連續空行
    content = re.sub(r'\n{3,}', '\n\n', content)

    # ==========================================

    # 7. 組合內容 (包含新的 severity 欄位)
    # 注意：severity 後面一定要有空格
    full_content = f"""---
layout: post
title:  "{title}"
date:   {time_str}
categories: [{category}]
severity: {severity}
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