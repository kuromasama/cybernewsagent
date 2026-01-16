import google.generativeai as genai
from groq import Groq
import os
import time

# ================= 設定區 =================
# Gemini 設定
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
# 建議使用 Pro 模型以獲得更長、更精準的輸出 (1.5 Pro 讀長文最強)
GEMINI_MODEL = 'models/gemini-1.5-pro' 

# Groq 設定
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
# Llama 3 70B 是目前 Groq 上推理能力最強的模型
GROQ_MODEL = 'llama3-70b-8192' 

# ================= 核心引擎函式 =================

def _call_gemini(prompt):
    """ 引擎 A: Google Gemini (擅長長文與中文流暢度) """
    print("   🤖 [Engine] 嘗試使用 Gemini 生成...")
    try:
        model = genai.GenerativeModel(GEMINI_MODEL)
        # 放寬安全設定，避免資安攻擊語法被誤判為惡意內容
        safety = [
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
        ]
        # 設定 temperature 為 0.2，讓技術輸出更精確、不亂發揮
        generation_config = genai.types.GenerationConfig(temperature=0.2)
        
        response = model.generate_content(prompt, safety_settings=safety, generation_config=generation_config)
        return response.text
    except Exception as e:
        print(f"   ⚠️ Gemini 生成失敗: {e}")
        return None

def _call_groq(prompt):
    """ 引擎 B: Groq (Llama 3) (擅長結構化與不受審查限制) """
    print("   🚀 [Engine] 切換至 Groq (Llama-3)...")
    if not GROQ_API_KEY:
        print("   ❌ 未設定 GROQ_API_KEY，無法切換。")
        return None
        
    try:
        client = Groq(api_key=GROQ_API_KEY)
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "你是一位世界級的資安威脅情資分析師 (Cyber Threat Intelligence Analyst)。請根據用戶提供的技術報告，撰寫極度詳盡的繁體中文分析。"
                },
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            model=GROQ_MODEL,
            temperature=0.2, # 低隨機性，追求精確
        )
        return chat_completion.choices[0].message.content
    except Exception as e:
        print(f"   ❌ Groq 生成失敗: {e}")
        return None

# ================= 主邏輯 =================

def generate_deep_dive(title, full_content, url):
    print(f"🧠 AI 正在深度分析：{title}...")

    # 🔥🔥🔥 這裡使用您指定的【深度版 Prompt】 🔥🔥🔥
    prompt = f"""
    你是一位世界級的資安威脅情資分析師 (Cyber Threat Intelligence Analyst)。
    你現在收到一份原始的技術報告，請根據這份內容，撰寫一份**極度詳盡、技術導向**的繁體中文分析報告。

    【原始報告內容】
    {full_content[:25000]} # Gemini Pro 視窗很大，我們盡量多給一點內容 (Groq 會自動截斷多餘的)
    
    【任務目標】
    這份報告是用於企業資安團隊 (Blue Team) 進行防禦部署，以及紅隊 (Red Team) 進行模擬攻擊使用。
    內容必須**精確**、**可執行**，嚴禁空泛的廢話。

    【輸出格式 (Markdown)】
    
    # 🚨 (中文標題 - 請翻譯得專業且聳動)

    ## 1. 執行摘要 (Executive Summary)
    - **風險等級**：(Critical / High / Medium - 請根據內容判斷)
    - **影響範圍**：(具體列出受影響的軟體版本、OS、硬體)
    - **事件簡述**：(用 100 字以內說明發生什麼事)

    ## 2. 🔍 技術原理深度剖析 (Technical Deep Dive)
    *請詳細解釋漏洞或攻擊的運作原理。*
    - **CVE 編號**：(如果有)
    - **漏洞類型**：(如 RCE, XSS, Buffer Overflow)
    - **MITRE ATT&CK 對應**：(請列出對應的 TTPs，例如 T1190 Exploit Public-Facing Application)
    - **攻擊鏈路圖解**：(請用文字描述攻擊流程：Step 1 -> Step 2 -> Step 3)

    ## 3. ⚔️ 紅隊視角：攻擊模擬 (Red Team POC)
    *想像你是一名滲透測試人員，你會如何利用這個漏洞？*
    - **前置條件**：(攻擊者需要什麼權限或網路環境？)
    - **攻擊向量**：(透過 Email? API? 惡意封包？)
    - **模擬步驟**：
      1. (詳細步驟 1)
      2. (詳細步驟 2)
      *若原文有提及程式碼或 Payload 邏輯，請務必在此解釋其運作方式。*

    ## 4. 🛡️ 藍隊視角：防禦與緩解 (Blue Team Mitigation)
    *給予系統管理員具體的設定建議。*
    - **IOCs (入侵指標)**：(列出原文提到的 IP、Hash、Domain，若無則標示「未提供」)
    - **修補建議**：(更新到哪個版本？)
    - **臨時緩解措施**：(如果無法更新，該怎麼設定防火牆或 WAF 規則？)
    - **偵測規則建議**：(例如：監控哪些 Log 關鍵字？)

    ## 5. 🔗 參考來源
    - [原始報告]({url})
    
    (注意：保持語氣專業、冷靜。所有技術名詞請保留英文，並在括號內做簡短中文解釋。)
    """

    # --- 策略執行 (Failover Strategy) ---
    
    # 1. 優先嘗試 Gemini (因為 Context Window 大，讀長文最完整)
    result = _call_gemini(prompt)
    
    # 2. 如果 Gemini 失敗 (可能因為內容太敏感被擋，或 API 錯誤)
    if not result:
        print("   ⚠️ Gemini 失敗或被阻擋，啟動 Groq (Llama-3) 救援模式！")
        
        # 注意：Groq 的 Context Window 較小 (約 8k)，如果文章太長可能會報錯
        # 這裡做一個簡單的截斷保護，確保 Prompt 不會爆掉 Groq 的限制
        safe_content_len = 15000 # 保守估計
        if len(full_content) > safe_content_len:
             # 如果原文太長，為了 Groq 必須縮減，重新組裝 Prompt
             prompt = prompt.replace(full_content[:25000], full_content[:safe_content_len])
             
        result = _call_groq(prompt)
        
    return result