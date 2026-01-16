import os
from dotenv import load_dotenv

# 載入 .env 檔案 (本地測試用)
load_dotenv()

# ================= API 金鑰 =================
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# ================= 模型設定 (2026 最新版) =================
# 主力：Gemini 3 Flash (速度快、Context 大)
GEMINI_MODEL = 'models/gemini-3-flash' 
# 備援：Llama 3.3 (邏輯強)
GROQ_MODEL = 'llama-3.3-70b-versatile'

# ================= RSS 訂閱列表 =================
# 這裡是可以自動化賺錢的源頭，建議選高質量的資安新聞源
# RSS_FEEDS = [
#     "https://feeds.feedburner.com/TheHackersNews",      # 駭客新聞 (必讀)
#     "https://www.bleepingcomputer.com/feed/",           # 技術細節多
#     "https://threatpost.com/feed/",                     # 威脅情報
#     "https://www.darkreading.com/rss.xml",              # 企業資安
#     "https://feeds.feedburner.com/securityweek",        # 資安週報
#     "https://krebsonsecurity.com/feed/",                # ✅ 新增：Krebs 很優質且好抓
# ]
# ================= RSS 訂閱列表 =================
RSS_FEEDS = [
    # --- 國際頂級資安媒體 ---
    "https://feeds.feedburner.com/TheHackersNews",      # 必讀：更新快，廣度夠
    "https://www.bleepingcomputer.com/feed/",           # 必讀：技術細節非常多
    "https://krebsonsecurity.com/feed/",                # 深度調查報導
    
    # --- 官方與政府情報 (硬核藍隊資料) ---
    "https://www.cisa.gov/uscert/ncas/alerts.xml",      # 美國 CISA 警報 (最權威來源)
    
    # --- 中文在地觀點 ---
    "https://www.ithome.com.tw/rss",                    # 台灣 iThome (增加在地相關性)
    
    # --- 暫時關閉 (防火牆太嚴格，容易 403) ---
    # "https://www.darkreading.com/rss.xml",
    # "https://feeds.feedburner.com/securityweek",
]
# ================= 檔案路徑設定 =================
# 記錄已處理過的連結，避免重複發文
PROCESSED_FILE = "data/processed_urls.txt"

# 輸出的文章路徑 (對應 GitHub Pages 的 docs 資料夾)
OUTPUT_DIR = "docs/_posts"