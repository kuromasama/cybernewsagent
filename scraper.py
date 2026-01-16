import trafilatura
import requests
import random
import time

def fetch_full_content(url):
    """
    從 URL 抓取完整的網頁內文 (超級偽裝版，模擬真實 Chrome)
    """
    # 這是最新的 Chrome 瀏覽器指紋
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'en-US,en;q=0.9,zh-TW;q=0.8,zh;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br',
        'Referer': 'https://www.google.com/',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'cross-site',
        'Sec-Fetch-User': '?1',
        'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"Windows"'
    }

    try:
        # 使用 Session 來保持連線狀態，有助於繞過某些防火牆
        session = requests.Session()
        response = session.get(url, headers=headers, timeout=20)
        
        # 檢查是否成功
        if response.status_code == 403:
            print(f"   🛡️ 403 被阻擋 (WAF): {url} - 嘗試更換 User-Agent 重試...")
            # 簡單重試機制：換個 User-Agent
            headers['User-Agent'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15'
            time.sleep(2)
            response = requests.get(url, headers=headers, timeout=20)

        response.raise_for_status()
        response.encoding = response.apparent_encoding

        # 解析 HTML
        text = trafilatura.extract(response.text, include_comments=False, include_tables=True)
        
        if text and len(text) > 200:
            return text
        else:
            print(f"   ⚠️ 內容過短: {url}")
            return None

    except Exception as e:
        # 這裡只印出錯誤代碼，不印整串，版面比較乾淨
        print(f"   ❌ 抓取失敗: {url} | Status: {getattr(e.response, 'status_code', 'N/A')} | {str(e)[:50]}")
    
    return None