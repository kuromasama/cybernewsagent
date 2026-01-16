# main.py
import feedparser
import os
import time
from datetime import datetime
from dotenv import load_dotenv
from scraper import fetch_full_content
from ai_analyst import generate_deep_dive
from publisher import save_to_hugo # 假設我們之後寫這個

load_dotenv()

# 資安 RSS 列表 (建議選高質量的)
RSS_FEEDS = [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
    "https://threatpost.com/feed/"
]

PROCESSED_FILE = "data/processed_urls.txt"

def load_processed():
    if not os.path.exists(PROCESSED_FILE): return set()
    with open(PROCESSED_FILE, "r") as f:
        return set(line.strip() for line in f)

def save_processed(url):
    with open(PROCESSED_FILE, "a") as f:
        f.write(f"{url}\n")

def main():
    processed_urls = load_processed()
    print(f"📂 已處理過的文章數：{len(processed_urls)}")

    for feed_url in RSS_FEEDS:
        print(f"📡 正在掃描 RSS: {feed_url}")
        feed = feedparser.parse(feed_url)

        for entry in feed.entries[:3]: # 每次每個 RSS 只抓最新 3 篇，避免 API 爆量
            link = entry.link
            title = entry.title
            
            # 1. 檢查是否處理過
            if link in processed_urls:
                continue
            
            print(f"⚡ 發現新文章：{title}")
            
            # 2. 爬蟲：抓取全文 (關鍵步驟！)
            full_text = fetch_full_content(link)
            if not full_text:
                print("   ⚠️ 無法抓取內文，跳過。")
                continue
            
            # 3. AI：深度分析
            article_content = generate_deep_dive(title, full_text, link)
            if not article_content:
                continue

            # 4. 發佈 (存成 Markdown)
            # 這裡我們先簡單存檔，之後接 GitHub Pages
            filename = f"website/_posts/{datetime.now().strftime('%Y-%m-%d')}-{title.replace(' ', '-').replace('/', '')}.md"
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            
            with open(filename, "w", encoding="utf-8") as f:
                # 加上 Jekyll/Hugo 需要的 Front Matter
                f.write(f"---\ntitle: \"{title}\"\ndate: {datetime.now().isoformat()}\n---\n\n")
                f.write(article_content)
                
            print(f"✅ 文章已生成：{filename}")
            
            # 5. 記錄並冷卻
            save_processed(link)
            print("⏳ 冷卻 30 秒以防 API 限制...")
            time.sleep(30)

if __name__ == "__main__":
    main()