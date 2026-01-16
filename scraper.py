import trafilatura
import random
import time

def fetch_full_content(url):
    """
    [Back to Basics] 使用 trafilatura 原生下載功能
    這通常比手動偽造 Headers 更穩定，因為它會自動處理編碼與重導向
    """
    try:
        # 簡單的隨機延遲，避免過快被擋
        time.sleep(random.uniform(1, 3))
        
        # 使用 trafilatura 下載
        downloaded = trafilatura.fetch_url(url)
        
        if downloaded:
            # 解析內容
            text = trafilatura.extract(downloaded, include_comments=False, include_tables=True)
            
            if text and len(text) > 200:
                return text
            else:
                print(f"   ⚠️ 內容過短或無法解析: {url}")
        else:
            print(f"   ⚠️ 下載回傳為空 (可能被擋): {url}")
            
    except Exception as e:
        print(f"   ❌ 抓取異常: {url} | {e}")
    
    return None