import os
import re
from datetime import datetime

def save_to_jekyll(title, content, category="security", output_dir="docs/_posts"):
    """
    將內容轉換為 Jekyll/GitHub Pages 格式的 Markdown
    """
    # 1. 準備時間與檔名
    today = datetime.now()
    date_str = today.strftime("%Y-%m-%d")
    # Jekyll 需要這種時間格式：YYYY-MM-DD HH:MM:SS +0800
    time_str = today.strftime("%Y-%m-%d %H:%M:%S +0000") 
    
    # 處理檔名 (去除不合法字元)
    safe_title = title.replace(" ", "-").replace("/", "-").replace(":", "").replace("?", "")
    filename = f"{date_str}-{safe_title}.md"
    filepath = os.path.join(output_dir, filename)
    
    # 2. 插入被動收入 (暫時關閉)
    affiliate_block = ""
    
    # ⬇️ 這裡我先幫您註解掉了，等申請到連結後，把下面這幾行的 '#' 拿掉即可
    # if category == "security":
    #     affiliate_block = """
    # \n
    # ---
    # ### 🔒 資安專家推薦
    # * **NordVPN**：保護您的網路足跡，防止駭客追蹤。[👉 點此查看優惠](您的連結)
    # * **Ledger 冷錢包**：保護加密資產的最佳實體錢包。[👉 了解更多](您的連結)
    # ---
    # """
    
    # 3. 組合內容 (Jekyll Front Matter + 正文 + 廣告區塊)
    # 注意：title 兩邊要有引號，避免標題中有冒號導致格式錯誤
    # ----------------------------------------------------
    # 🧹 自動排版修復器 (Magic Auto-Formatter)
    # ----------------------------------------------------
    
    # 1. 修復 Code Block: 如果 ``` 沒有換行，強制補上兩個換行
    # 將 "文字: ```" 變成 "文字:\n\n```"
    content = re.sub(r'([^\n])\s*```', r'\1\n\n```', content)
    
    # 2. 修復 Code Block 結尾: 確保 ``` 結尾後也有換行
    content = re.sub(r'```([^\n])', r'```\n\1', content)

    # 3. 修復表格: 如果表格標題列 (|...|) 前面沒有空行，強制補上
    # 偵測到 "| 標題 |" 且前面不是換行時，插入換行
    content = re.sub(r'([^\n])\n(\|.*\|.*\|)', r'\1\n\n\2', content)
    
    # ----------------------------------------------------

    # 3. 組合內容 (Jekyll Front Matter + 正文)
    full_content = f"""---
layout: post
title:  "{title}"
date:   {time_str}
categories: [{category}]
---

{content}

{affiliate_block}
"""

    # 4. 寫入檔案
    try:
        # 確保目錄存在
        os.makedirs(output_dir, exist_ok=True)
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(full_content)
        print(f"✅ [Publisher] 文章已生成：{filename}")
        return filepath
    except Exception as e:
        print(f"❌ [Publisher] 存檔失敗: {e}")
        return None
