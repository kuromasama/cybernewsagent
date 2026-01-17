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
    # ✨ NEW: 動態威脅等級分析 + Emoji (v5.0)
    # ================================================
    severity = "info"
    # 找中文或英文等級
    severity_match = re.search(r'\*\*(嚴重等級|Severity)\*\*:\s*([\u4e00-\u9fa5a-zA-Z]+)', content, re.IGNORECASE)
    
    if severity_match:
        level_text = severity_match.group(2).strip().lower()
        level_map = {
            "極高": "critical", "critical": "critical", "嚴重": "critical",
            "高": "high", "high": "high",
            "中": "medium", "medium": "medium",
            "低": "info", "low": "info", "info": "info"
        }
        severity = level_map.get(level_text, "info")
    
    # 決定 Emoji
    emoji_map = {
        "critical": "🚨", "high": "🔥", "medium": "⚠️", "info": "🛡️"
    }
    icon = emoji_map.get(severity, "🛡️")
    
    print(f"   🔍 威脅分析: {severity.upper()} {icon}")

    # ==========================================
    # 🧹 Auto-Formatter (自動排版修復引擎)
    # ==========================================
    
    # 1. 表格前置修復
    content = re.sub(r'([^\n])\n([ \t]*\|)', r'\1\n\n\2', content)
    
    # 2. Code Block 修復
    content = re.sub(r'([^\n])\s*```', r'\1\n\n```', content)
    content = re.sub(r'```([^\n])', r'```\n\n\1', content)
    
    # 3. 表格深度修復 (移除縮排)
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

    # 4. 智慧縮排 Code Block
    def indent_code_block(match):
        list_line = match.group(1)
        code_block = match.group(2)
        indented_block = code_block.replace('\n', '\n    ')
        return f"{list_line}\n\n    {indented_block}"
    content = re.sub(r'([\*\-]\s+.*?:)\s*\n+(```[\s\S]*?```)', indent_code_block, content)
    
    # 5. 替換舊警鈴 Emoji
    content = content.replace("🚨", icon)
    
    # 6. 移除多餘空行
    content = re.sub(r'\n{3,}', '\n\n', content)

    # ==========================================
    # 💰 Affiliate Block (保留被動收入區塊)
    # ==========================================
    affiliate_block = ""
    # if category == "security":
    #     affiliate_block = f"""
    #     \n
    #     ---
    #     ### 🔒 資安專家推薦
    #     * **NordVPN**：保護您的網路足跡，防止駭客追蹤。[👉 點此查看優惠](您的連結)
    #     * **Ledger 冷錢包**：保護加密資產的最佳實體錢包。[👉 了解更多](您的連結)
    #     ---
    #     """

    # 7. 組合內容
    full_content = f"""---
layout: post
title:  "{title}"
date:   {time_str}
categories: [{category}]
severity: {severity}
---

{content}

{affiliate_block}
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