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
RSS_FEEDS = [
    "https://feeds.feedburner.com/TheHackersNews",      # 駭客新聞 (必讀)
    "https://www.bleepingcomputer.com/feed/",           # 技術細節多
    "https://threatpost.com/feed/",                     # 威脅情報
    "https://www.darkreading.com/rss.xml",              # 企業資安
    "https://feeds.feedburner.com/securityweek",        # 資安週報
]

# ================= 檔案路徑設定 =================
# 記錄已處理過的連結，避免重複發文
PROCESSED_FILE = "data/processed_urls.txt"

# 輸出的文章路徑 (對應 GitHub Pages 的 docs 資料夾)
OUTPUT_DIR = "docs/_posts"