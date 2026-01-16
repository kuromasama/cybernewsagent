# scraper.py
import trafilatura
import requests

def fetch_full_content(url):
    """
    從 URL 抓取完整的網頁內文 (去除廣告、選單)
    """
    try:
        downloaded = trafilatura.fetch_url(url)
        if downloaded:
            # 提取正文，並包含一些格式 (如粗體、標題)
            text = trafilatura.extract(downloaded, include_comments=False, include_tables=True)
            if text and len(text) > 500: # 確保抓到的內容夠長
                return text
    except Exception as e:
        print(f"❌ 爬蟲失敗 {url}: {e}")
    
    return None # 如果抓取失敗，回傳 None