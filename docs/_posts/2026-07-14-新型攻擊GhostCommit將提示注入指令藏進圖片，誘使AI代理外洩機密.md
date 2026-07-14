---
layout: post
title:  "新型攻擊GhostCommit將提示注入指令藏進圖片，誘使AI代理外洩機密"
date:   2026-07-14 01:50:58 +0000
categories: [security]
severity: critical
---

# 🚨 解析 GhostCommit 攻擊：圖片中藏著的惡意指令
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Info Leak (敏感資料外洩)
> * **關鍵技術**: Steganography (隱寫術), AI-powered Code Review (人工智慧程式碼審查)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: GhostCommit 攻擊利用人工智慧程式碼審查工具的限制，將惡意指令藏在 PNG 圖片中，避開文字差異的檢查。
* **攻擊流程圖解**:
  1. 攻擊者新增代理指示文件 `AGENTS.md`，指定圖片為建置規格的正式來源。
  2. 圖片中藏著惡意指令，要求代理讀取 `.env` 檔案並將其內容轉為整數序列。
  3. 代理工具讀取圖片並執行指令，將 `.env` 檔案內容寫入程式碼中。
* **受影響元件**: 受影響的元件包括使用人工智慧程式碼審查工具的開發環境，特別是那些使用 PNG 圖片作為建置規格的正式來源的環境。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有權限新增代理指示文件 `AGENTS.md` 和圖片檔案。
* **Payload 建構邏輯**:

    ```
    
    python
    # 範例指令
    import os
    
    # 讀取 .env 檔案內容
    with open('.env', 'rb') as f:
        env_content = f.read()
    
    # 將 .env 檔案內容轉為整數序列
    env_sequence = [byte for byte in env_content]
    
    # 寫入程式碼中
    with open('code.py', 'w') as f:
        f.write('env_sequence = {}'.format(env_sequence))
    
    ```
* **繞過技術**: 攻擊者可以使用 Steganography 技術將惡意指令藏在圖片中，避開人工智慧程式碼審查工具的檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  | `AGENTS.md` |
|  |  |  | `docs/images/build-spec.png` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule GhostCommit_Attack {
        meta:
            description = "GhostCommit 攻擊偵測"
            author = "Your Name"
        strings:
            $png_header = { 89 50 4E 47 0D 0A 1A 0A }
            $env_sequence = { 65 6E 76 5F 73 65 71 75 65 6E 63 65 }
        condition:
            $png_header at 0 and $env_sequence
    }
    
    ```
* **緩解措施**: 開發人員應該避免使用 PNG 圖片作為建置規格的正式來源，改用文字檔案或其他安全的方法。另外，開發人員應該定期審查程式碼和代理指示文件，確保沒有惡意指令。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Steganography (隱寫術)**: 一種將秘密信息藏在圖片、音頻或其他檔案中的技術。想像將一張圖片藏在另一張圖片中，技術上是指使用最少的位元組來儲存秘密信息。
* **AI-powered Code Review (人工智慧程式碼審查)**: 一種使用人工智慧技術來審查程式碼的方法。想像有一個機器人可以幫助你檢查程式碼的錯誤和安全性問題，技術上是指使用機器學習算法來分析程式碼的語法和語義。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/177271)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


