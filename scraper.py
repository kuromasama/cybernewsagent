import trafilatura
import requests
import random
import time

def fetch_full_content(url):
    """
    從 URL 抓取完整的網頁內文 (偽裝成瀏覽器以繞過防爬蟲機制)
    """
    # 隨機選一個 User-Agent，讓行為更像真人
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ]
    
    headers = {
        'User-Agent': random.choice(user_agents),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Referer': 'https://www.google.com/'
    }

    try:
        # 1. 使用 requests 下載 (這一步可以處理 Redirect 和 Headers)
        # 設定 timeout 避免卡死
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status() # 如果 404 或 403 會報錯
        
        # 2. 確保編碼正確
        response.encoding = response.apparent_encoding

        # 3. 使用 trafilatura 解析下載回來的 HTML 字串
        text = trafilatura.extract(response.text, include_comments=False, include_tables=True)
        
        if text and len(text) > 300: # 確保內容長度足夠
            return text
        else:
            print(f"   ⚠️ 內容太短或無法解析: {url}")
            return None

    except Exception as e:
        print(f"   ❌ 爬蟲失敗 (被擋或連線逾時): {url} | Error: {str(e)[:100]}")
    
    return None