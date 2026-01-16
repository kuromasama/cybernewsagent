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
    # --- 🟢 第一梯隊：即時新聞 (廣度) ---
    # --- 國際頂級資安媒體 ---
    "https://feeds.feedburner.com/TheHackersNews",      # 必讀：更新快
    "https://www.bleepingcomputer.com/feed/",           # 必讀：技術細節多
    "https://krebsonsecurity.com/feed/",                # 深度調查報導
    
    # --- 🔵 第二梯隊：官方警報 (藍隊 IOCs 來源) ---
    "https://www.cisa.gov/uscert/ncas/alerts.xml",      # 美國 CISA (最權威)
    "https://www.twcert.org.tw/tw/rss-cp-104-1.xml",   # 台灣 TWCERT (在地化)

    # --- 🔴 第三梯隊：深度技術與威脅獵捕 (紅隊/逆向來源) ---
    # 這些來源文章較長，是 AI 發揮深度分析的最佳戰場
    "https://googleprojectzero.blogspot.com/feeds/posts/default", # Google 0-day 研究 (極硬核)
    "https://redcanary.com/feed/",                      # Red Canary (偵測規則寫得最好)
    "https://www.mandiant.com/resources/blog/rss.xml",  # Mandiant (APT 攻擊鏈分析)
    
    # --- 🟠 第四梯隊：在地觀點 ---
    "https://www.ithome.com.tw/rss",                    # iThome 資安新聞

    # --- 暫時關閉 (防火牆太嚴格，容易 403) ---
    # "https://www.darkreading.com/rss.xml",
    # "https://feeds.feedburner.com/securityweek",
]

# ================= 檔案路徑設定 =================
# 記錄已處理過的連結，避免重複發文
PROCESSED_FILE = "data/processed_urls.txt"

# 輸出的文章路徑 (對應 GitHub Pages 的 docs 資料夾)
OUTPUT_DIR = "docs/_posts"