import os
from datetime import datetime

def save_to_jekyll(title, content, category="security", output_dir="docs/_posts"):
    """
    將內容轉換為 Jekyll/GitHub Pages 格式的 Markdown，並插入聯盟行銷連結
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
    
    # 2. 插入被動收入 (聯盟行銷) 區塊
    # 這就是您未來的獲利來源，AI 會自動把它貼在每篇文章下面
    affiliate_block = ""
    if category == "security":
        affiliate_block = """
\n
---
### 🔒 資安專家推薦
* **NordVPN**：保護您的網路足跡，防止駭客追蹤。[👉 點此查看優惠](https://nordvpn.com/)
* **Ledger 冷錢包**：保護加密資產的最佳實體錢包。[👉 了解更多](https://www.ledger.com/)
---
"""
    
    # 3. 組合內容 (Jekyll Front Matter + 正文 + 廣告)
    # 注意：title 兩邊要有引號，避免標題中有冒號導致格式錯誤
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