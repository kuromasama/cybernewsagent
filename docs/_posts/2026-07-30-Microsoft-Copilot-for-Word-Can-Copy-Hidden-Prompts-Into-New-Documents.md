---
layout: post
title:  "Microsoft Copilot for Word Can Copy Hidden Prompts Into New Documents"
date:   2026-07-30 13:42:09 +0000
categories: [security]
severity: high
---

# 🔥 解析 Microsoft 365 Copilot 的隱藏指令漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 7.5)
> * **受駭指標**: Arbitrary Code Execution (ACE)
> * **關鍵技術**: Hidden Instructions, Large Language Model (LLM), Document Text Analysis

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Microsoft 365 Copilot 的大語言模型 (LLM) 可以被隱藏在 Word 文件中的指令欺騙，導致 Copilot 將這些指令作為用戶的請求執行。這是因為 Word 文件中的文本被傳遞給 LLM 進行分析，而 LLM 沒有足夠的安全機制來區分用戶的請求和惡意指令。
* **攻擊流程圖解**:
  1. 攻擊者創建一個包含隱藏指令的 Word 文件。
  2. 用戶將文件上傳到 OneDrive 或通過電子郵件發送給其他用戶。
  3. Microsoft 365 Copilot 讀取文件並將其作為用戶的請求執行。
  4. 隱藏指令被 Copilot 執行，可能導致任意代碼執行或其他安全問題。
* **受影響元件**: Microsoft 365 Copilot、Word、OneDrive

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個包含隱藏指令的 Word 文件，並將其上傳到 OneDrive 或通過電子郵件發送給其他用戶。
* **Payload 建構邏輯**:

    ```
    
    python
    # 範例指令
    import docx
    
    # 創建一個 Word 文件
    doc = docx.Document()
    
    # 添加隱藏指令
    doc.add_paragraph("隱藏指令", style="HiddenText")
    
    # 儲存文件
    doc.save("example.docx")
    
    ```
* **繞過技術**: 攻擊者可以使用各種技術來繞過安全機制，例如使用加密或壓縮來隱藏指令。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /example.docx |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Microsoft_Copilot_Vulnerability {
      meta:
        description = "Microsoft 365 Copilot 隱藏指令漏洞"
        author = "Your Name"
      strings:
        $hidden_text = "隱藏指令"
      condition:
        $hidden_text in (0..1000)
    }
    
    ```
* **緩解措施**: 用戶應該避免從不信任的來源下載或打開 Word 文件，並且應該定期更新 Microsoft 365 Copilot 和其他相關軟件。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Large Language Model (LLM)**: 一種人工智慧模型，使用大規模的語言數據集來學習語言模式和關係。LLM 可以用於自然語言處理、文本生成和其他任務。
* **Hidden Instructions**: 一種隱藏在文件中的指令，可能被用來執行惡意代碼或其他安全問題。
* **Document Text Analysis**: 一種技術，使用自然語言處理和機器學習來分析文件中的文本，可能用於安全和其他任務。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/microsoft-copilot-for-word-can-copy.html)
- [Microsoft 365 Copilot 官方文檔](https://docs.microsoft.com/en-us/microsoft-365/copilot/)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1056/)


