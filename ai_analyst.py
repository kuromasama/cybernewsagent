import google.generativeai as genai
from groq import Groq
import os
import time

# ================= 2026 模型配置 =================
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
GEMINI_MODEL = 'models/gemini-3-flash' 
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = 'llama-3.3-70b-versatile' 

# ================= 核心引擎函式 =================

def _call_gemini(prompt):
    print(f"   ⚡ [Engine] 使用 Gemini 3 Flash 進行深度剖析...")
    try:
        model = genai.GenerativeModel(GEMINI_MODEL)
        safety = [
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
        ]
        generation_config = genai.types.GenerationConfig(
            temperature=0.15,
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
                {"role": "system", "content": "你是一位世界級的資安逆向工程師與威脅情報專家。"},
                {"role": "user", "content": prompt}
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

    # 1. 讀取 Prompt (優先從 Secret，失敗則從本地備份檔)
    raw_prompt = os.getenv("AI_PROMPT_TEMPLATE")
    
    if not raw_prompt:
        try:
            with open("prompt_backup.txt", "r", encoding="utf-8") as f:
                raw_prompt = f.read()
            print("   📂 [Local] 已讀取本地 prompt_backup.txt")
        except FileNotFoundError:
            print("   ❌ [Error] 找不到 AI_PROMPT_TEMPLATE 也找不到 prompt_backup.txt")
            return None

    # 2. 注入變數 (關鍵步驟)
    # 將 Secret 中的 {context} 替換為實際文章內容 (截斷前 60000 字以防爆 Token)
    # 將 {url} 替換為實際網址
    prompt = raw_prompt.replace("{context}", full_content[:60000]).replace("{url}", url)

    # --- 執行策略 ---
    result = _call_gemini(prompt)
    
    if not result:
        print("   ⚠️ Gemini 失敗，啟動 Groq 救援模式！")
        safe_len = 25000 
        if len(full_content) > safe_len:
             prompt = prompt.replace(full_content[:60000], full_content[:safe_len])
        result = _call_groq(prompt)
        
    return result