import feedparser
import time
import os
# 🔥 修正: 從 config 匯入設定，讓程式碼更乾淨
from config import RSS_FEEDS, PROCESSED_FILE
from scraper import fetch_full_content
from ai_analyst import generate_deep_dive
from publisher import save_to_jekyll 

def load_processed():
    # 確保 data 資料夾存在
    os.makedirs(os.path.dirname(PROCESSED_FILE), exist_ok=True)
    
    if not os.path.exists(PROCESSED_FILE): 
        return set()
    
    with open(PROCESSED_FILE, "r") as f:
        return set(line.strip() for line in f)

def save_processed(url):
    with open(PROCESSED_FILE, "a") as f:
        f.write(f"{url}\n")

def main():
    processed_urls = load_processed()
    print(f"📂 已處理過的文章數：{len(processed_urls)}")

    # 從 config.py 讀取 RSS 列表
    for feed_url in RSS_FEEDS:
        print(f"📡 正在掃描 RSS: {feed_url}")
        try:
            feed = feedparser.parse(feed_url)
        except Exception as e:
            print(f"   ❌ RSS 讀取錯誤: {e}")
            continue

        # 每次只抓最新 2 篇 (避免一次跑太久被 GitHub 砍掉)
        for entry in feed.entries[:2]: 
            link = entry.link
            title = entry.title
            
            # 1. 檢查是否處理過
            if link in processed_urls:
                continue
            
            print(f"⚡ 發現新文章：{title}")
            
            # 2. 爬蟲：抓取全文
            full_text = fetch_full_content(link)
            if not full_text:
                print("   ⚠️ 無法抓取內文，跳過。")
                continue
            
            # 3. AI：深度分析 (這裡會自動切換 Gemini / Groq)
            article_content = generate_deep_dive(title, full_text, link)
            if not article_content:
                continue

            # 4. 發佈 (自動存檔 + 插入被動收入廣告)
            save_path = save_to_jekyll(
                title=title,
                content=article_content,
                category="security"
            )
            
            if save_path:
                # 5. 記錄並冷卻
                save_processed(link)
                print("⏳ 冷卻 10 秒以防 API 限制...")
                time.sleep(10)

if __name__ == "__main__":
    main()