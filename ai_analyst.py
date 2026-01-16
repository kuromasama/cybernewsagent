import google.generativeai as genai
from groq import Groq
import os
import time

# ================= 2026 最新模型配置 =================

# 設定 API Key
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

# ⚡ 主力引擎：Gemini 3 Flash
# 特性：極速、超大 Context Window、對程式碼理解力大幅提升
GEMINI_MODEL = 'models/gemini-3-flash' 

# 🚀 救援引擎：Groq (Llama 3.3)
# 特性：開源最強邏輯，作為備援
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = 'llama-3.3-70b-versatile' 

# ================= 核心引擎函式 =================

def _call_gemini(prompt):
    """ 引擎 A: Google Gemini 3 Flash """
    print(f"   ⚡ [Engine] 使用 Gemini 3 Flash 生成中...")
    try:
        model = genai.GenerativeModel(GEMINI_MODEL)
        
        # 安全設定：全面放寬，確保資安攻擊語法 (POC) 不被誤殺
        safety = [
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
        ]
        
        # 參數微調：Gemini 3 理解力強，Temperature 0.1 確保技術精確度
        generation_config = genai.types.GenerationConfig(
            temperature=0.1,
            max_output_tokens=16384 # Gemini 3 Flash 支援更長的輸出
        )
        
        response = model.generate_content(prompt, safety_settings=safety, generation_config=generation_config)
        return response.text
    except Exception as e:
        print(f"   ⚠️ Gemini 生成失敗: {e}")
        return None

def _call_groq(prompt):
    """ 引擎 B: Groq (Llama 3.3) """
    print(f"   🚀 [Engine] 切換至 Groq ({GROQ_MODEL})...")
    if not GROQ_API_KEY:
        print("   ❌ 未設定 GROQ_API_KEY，無法切換。")
        return None
        
    try:
        client = Groq(api_key=GROQ_API_KEY)
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "你是一位世界級的資安威脅情資分析師 (CISO Level)，擅長撰寫繁體中文的紅藍隊攻防報告。你的輸出必須極度詳盡、技術導向，並且嚴格遵守 Markdown 格式。"
                },
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            model=GROQ_MODEL,
            temperature=0.1,
            max_tokens=8000,
        )
        return chat_completion.choices[0].message.content
    except Exception as e:
        print(f"   ❌ Groq 生成失敗: {e}")
        return None

# ================= 主邏輯 =================

def generate_deep_dive(title, full_content, url):
    print(f"🧠 AI 正在深度分析：{title}...")

    # 🔥 極度詳盡版 Prompt (不縮減)
    prompt = f"""
    你是一位世界級的資安威脅情資分析師 (Cyber Threat Intelligence Analyst)。
    你現在收到一份原始的技術報告，請根據這份內容，撰寫一份**極度詳盡、技術導向**的繁體中文分析報告。

    【原始報告內容 (Context)】
    {full_content[:50000]} # Gemini 3 Flash 吃得下非常多內容，我們提升截取上限到 5 萬字
    
    【任務目標】
    這份報告是用於企業資安團隊 (Blue Team) 進行防禦部署，以及紅隊 (Red Team) 進行模擬攻擊使用。
    內容必須**精確**、**可執行 (Actionable)**，嚴禁空泛的廢話。

    【輸出格式 (Strict Markdown)】
    
    # 🚨 (中文標題 - 請翻譯得專業且聳動)

    ## 1. 執行摘要 (Executive Summary)
    - **風險等級**：(Critical / High / Medium - 請根據 CVSS 或影響範圍判斷)
    - **影響範圍**：(具體列出受影響的軟體版本、OS、硬體型號)
    - **事件簡述**：(用 150 字以內說明攻擊發生的來龍去脈)

    ## 2. 🔍 技術原理深度剖析 (Technical Deep Dive)
    *請詳細解釋漏洞或攻擊的運作原理，這是報告的核心。*
    - **CVE 編號**：(若無則標示 N/A)
    - **漏洞類型**：(如 RCE, XSS, Buffer Overflow, Race Condition)
    - **MITRE ATT&CK 對應**：(請列出對應的 TTPs ID 與名稱，例如 [T1190] Exploit Public-Facing Application)
    - **攻擊鏈路圖解**：(請用文字箭頭圖描述：User Input -> Filter Bypass -> Memory Corruption -> Shellcode Execution)

    ## 3. ⚔️ 紅隊視角：攻擊模擬 (Red Team POC)
    *想像你是一名滲透測試人員，你會如何利用這個漏洞？*
    - **前置條件**：(攻擊者需要什麼權限？內網還是外網？需要使用者互動嗎？)
    - **攻擊向量**：(Payload 是透過 HTTP Header? JSON Body? 還是惡意檔案？)
    - **模擬步驟 (Step-by-Step)**：
      1. (詳細步驟 1：偵查)
      2. (詳細步驟 2：傳遞 Payload)
      3. (詳細步驟 3：觸發漏洞)
      *若原文有提及程式碼片段或 Payload 邏輯，請務必在此解釋其程式碼運作原理。*

    ## 4. 🛡️ 藍隊視角：防禦與緩解 (Blue Team Mitigation)
    *給予系統管理員具體的設定建議。*
    - **IOCs (入侵指標)**：(列出原文提到的 IP、Hash、Domain、Registry Key，若無則標示「未提供」)
    - **修補建議**：(更新到哪個版本？Patch ID 為何？)
    - **臨時緩解措施 (Workaround)**：(如果無法更新，該怎麼設定防火牆、WAF 規則或修改設定檔？)
    - **偵測規則建議**：(例如：在 SIEM 中監控哪些 Log 關鍵字或異常行為？)

    ## 5. 🔗 參考來源
    - [原始報告]({url})
    
    (注意：保持語氣專業、冷靜。所有專有技術名詞請保留英文，並在括號內做簡短中文解釋。)
    """

    # --- 雙引擎策略執行 (Failover Strategy) ---
    
    # 1. 優先嘗試 Gemini 3 Flash
    result = _call_gemini(prompt)
    
    # 2. 如果 Gemini 失敗
    if not result:
        print("   ⚠️ Gemini 失敗或被阻擋，啟動 Groq (Llama 3.3) 救援模式！")
        
        # Groq Context Window 保護機制
        safe_content_len = 20000 
        if len(full_content) > safe_content_len:
             prompt = prompt.replace(full_content[:50000], full_content[:safe_content_len])
             
        result = _call_groq(prompt)
        
    return result