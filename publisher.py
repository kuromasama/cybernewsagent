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
    # 🧹 Auto-Formatter (自動排版修復引擎 v3.0)
    # ==========================================
    
    # 1. 修復表格：只要看到 "|" 開頭的行，且前面不是空行，就強制加兩個換行
    content = re.sub(r'([^\n])\n(\|.*\|)', r'\1\n\n\2', content)
    
    # 2. 修復 Code Block：同理，強制在 ``` 前後加空行
    content = re.sub(r'([^\n])```', r'\1\n\n```', content)
    content = re.sub(r'```([^\n])', r'```\n\n\1', content)
    
    # 3. 【智慧縮排】(進階功能 - 保留)
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
    
    # 4. 移除多餘的連續空行 (美觀)
    content = re.sub(r'\n{3,}', '\n\n', content)

    # ==========================================

    # 5. 插入被動收入 (暫時關閉，等您申請好連結再來開啟)
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