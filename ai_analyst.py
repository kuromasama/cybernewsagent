import google.generativeai as genai
from groq import Groq
import os
import time

# ================= 2026 模型配置 =================
# 設定 API Key
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

# ⚡ 主力引擎：Gemini 3 Flash
# 只有它能處理超長 Context 並保持極高的邏輯連貫性
GEMINI_MODEL = 'models/gemini-3-flash' 

# 🚀 救援引擎：Groq (Llama 3.3)
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = 'llama-3.3-70b-versatile' 

# ================= 核心引擎函式 =================

def _call_gemini(prompt):
    print(f"   ⚡ [Engine] 使用 Gemini 3 Flash 進行深度剖析...")
    try:
        model = genai.GenerativeModel(GEMINI_MODEL)
        
        # 安全全開：為了生成攻擊 Payload 與惡意程式碼分析，必須關閉過濾
        safety = [
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
        ]
        
        generation_config = genai.types.GenerationConfig(
            temperature=0.15, # 稍微調高 0.05 讓它在解釋名詞時能更生動，但保持技術精確
            max_output_tokens=16384
        )
        
        response = model.generate_content(prompt, safety_settings=safety, generation_config=generation_config)
        return response.text
    except Exception as e:
        print(f"   ⚠️ Gemini 生成失敗: {e}")
        return None

def _call_groq(prompt):
    print(f"   🚀 [Engine] 切換至 Groq ({GROQ_MODEL})...")
    if not GROQ_API_KEY:
        print("   ❌ 未設定 GROQ_API_KEY")
        return None
        
    try:
        client = Groq(api_key=GROQ_API_KEY)
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "你是一位世界級的資安逆向工程師與威脅情報專家。你的任務是撰寫技術深度極高的分析報告，包含程式碼、指令與底層原理。"
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

    # 🔥 v3.0 硬核版 Prompt：要求代碼、指令與名詞解釋
    prompt = f"""
    你現在的身分是 **Elite Threat Hunter (菁英威脅獵人)** 與 **Reverse Engineer (逆向工程師)**。
    請分析以下原始技術情報，撰寫一份**教科書等級**的資安攻防技術白皮書。
    
    【目標受眾】
    資深資安工程師、滲透測試人員、SOC 分析師。內容不能太淺，必須深入到底層原理。

    【原始情報 (Context)】
    {full_content[:60000]} 
    
    ---
    
    【輸出格式規範 (Strict Markdown)】

    # 🚨 (標題：請翻譯得極具技術感，例如使用「解析」、「利用」、「防禦繞過」等詞)

    > **⚡ 戰情快篩 (TL;DR)**
    > * **嚴重等級**: (Critical / High / Medium - 附上 CVSS 分數若有)
    > * **受駭指標**: (一句話說明是 RCE, LPE 還是 Info Leak)
    > * **關鍵技術**: (列出 3-5 個關鍵字，如 `Heap Spraying`, `Deserialization`, `eBPF`)

    ## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
    *這裡不要寫新聞稿，要寫技術文件。*
    * **Root Cause**: 從程式碼層面解釋漏洞成因（例如：在哪個函數沒有檢查邊界？指針如何被釋放後重用？）。
    * **攻擊流程圖解**: 使用文字流程圖 (如 `User Input -> malloc() -> free() -> use-after-free`)。
    * **受影響元件**: 精確的版本號與環境。

    ## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
    *提供具體的攻擊手法，若原文無代碼，請根據漏洞類型推演可能的 PoC (Proof of Concept)。*
    * **攻擊前置需求**: (權限、網路位置)
    * **Payload 建構邏輯**: 
        * 請使用 **Code Block** 展示可能的 Payload 結構 (如 JSON, HTTP Request, Python Snippet)。
        * *範例指令*: 提供 `curl`, `nmap` 或 `metasploit` 模組的使用範例。
    * **繞過技術**: (如果有 WAF 或 EDR 繞過技巧，請務必詳述)

    ## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
    *不要只說「更新修補」，給我具體的規則。*
    * **IOCs (入侵指標)**: 表格列出 Hash, IP, Domain, File Path。
    * **偵測規則 (Detection Rules)**:
        * 請嘗試撰寫一條 **YARA Rule** 或 **Snort/Suricata Signature** 來偵測此攻擊。
        * 或者是具體的 **SIEM 查詢語法** (Splunk/Elastic)。
    * **緩解措施**: 除了 Patch 之外的 Config 修改建議 (例如 `nginx.conf` 設定、Registry 修改)。

    ## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
    *這部分至關重要。請從上述文章中挑選 3-5 個**最艱澀**或**最核心**的技術名詞進行深度解釋。*
    * **格式**:
        * **名詞 (英文)**: 中文解釋。使用「比喻」加上「技術定義」來說明。
        * *(範例) **Race Condition (競爭危害)**: 想像兩個人同時去改同一本帳簿。技術上是指多個執行緒同時存取共享記憶體，且至少有一個是寫入動作，導致數據不一致或邏輯錯誤。*

    ## 5. 🔗 參考文獻與延伸閱讀
    - [原始報告]({url})
    - (若你知道相關的 MITRE ATT&CK 編號，請列出並附上連結)

    (注意：保持語氣冷靜、客觀、極度專業。所有程式碼區塊必須標註語言。)
    """

    # --- 執行策略 ---
    
    result = _call_gemini(prompt)
    
    if not result:
        print("   ⚠️ Gemini 失敗，啟動 Groq 救援模式！")
        # Groq 安全截斷
        safe_len = 25000 
        if len(full_content) > safe_len:
             prompt = prompt.replace(full_content[:60000], full_content[:safe_len])
        result = _call_groq(prompt)
        
    return result
