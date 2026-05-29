---
layout: post
title:  "Kimsuky Deploys HTTPSpy, Expands Arsenal with HelloDoor and VS Code Tunnels"
date:   2026-05-29 09:40:41 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Kimsuky 威脅群體的 HTTPSpy 攻擊技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Social Engineering, Malware Disguise, JSONPing

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Kimsuky 威脅群體利用社會工程學手法，偽造安全軟體安裝頁面和 Cisco Webex 會議頁面，誘騙受害者下載惡意軟體。
* **攻擊流程圖解**:
  1. 受害者訪問偽造的安全軟體安裝頁面或 Webex 會議頁面。
  2. 下載並執行惡意軟體（例如 "nos-setup.exe" 或 "astx-setup.exe"）。
  3. 惡意軟體啟動第二階段 DLL Payload ("MemLoader.dll")。
  4. DLL Payload 建立持續性並聯繫 C2 伺服器下載額外 Payload。
* **受影響元件**: Windows 作業系統，尤其是使用 South Korean 安全軟體的用戶。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 受害者需要訪問偽造的安全軟體安裝頁面或 Webex 會議頁面。
* **Payload 建構邏輯**:

    ```
    
    python
    # 範例 Payload 結構
    payload = {
        "type": "http",
        "url": "http://example.com/malware.exe",
        "headers": {
            "User-Agent": "Mozilla/5.0"
        }
    }
    
    ```
* **繞過技術**: Kimsuky 威脅群體使用 JSONPing 技術來驗證惡意軟體的執行狀態，並使用合法的 Webex 會議頁面來分發惡意軟體。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\malware.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Kimsuky_Malware {
        meta:
            description = "Kimsuky Malware Detection"
            author = "Your Name"
        strings:
            $a = "http://example.com/malware.exe"
        condition:
            $a in (pe.imports)
    }
    
    ```
* **緩解措施**: 更新安全軟體，避免訪問可疑的網站，並使用防毒軟體掃描系統。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **JSONPing**: 一種技術，使用 JSONP (JSON with Padding) 來驗證惡意軟體的執行狀態。
* **Social Engineering**: 一種攻擊手法，利用人類心理弱點來誘騙受害者執行惡意動作。
* **DLL Payload**: 一種惡意軟體，使用 DLL (Dynamic Link Library) 來執行惡意代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/05/kimsuky-deploys-httpspy-expands-arsenal.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


