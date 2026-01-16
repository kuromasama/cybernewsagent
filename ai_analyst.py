# ai_analyst.py
import google.generativeai as genai
import os
import time

# 設定
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
# 建議使用 Pro 模型以獲得更長、更精準的輸出，若為了速度可用 Flash
MODEL_NAME = 'models/gemini-1.5-pro' 

def generate_deep_dive(title, full_content, url):
    model = genai.GenerativeModel(MODEL_NAME)
    
    print(f"🧠 AI 正在深度分析：{title}...")

    # 🔥 超詳細 Prompt：要求 AI 根據「全文」進行分析
    prompt = f"""
    你是一位世界級的資安威脅情資分析師 (Cyber Threat Intelligence Analyst)。
    你現在收到一份原始的技術報告，請根據這份內容，撰寫一份**極度詳盡、技術導向**的繁體中文分析報告。

    【原始報告內容】
    {full_content[:15000]} # 避免超過 Token 限制，截取前 15000 字
    
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

    try:
        # 使用安全設定，避免技術內容被誤判為有害
        safety = [
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
        ]
        response = model.generate_content(prompt, safety_settings=safety)
        return response.text
    except Exception as e:
        print(f"AI 生成失敗: {e}")
        return None