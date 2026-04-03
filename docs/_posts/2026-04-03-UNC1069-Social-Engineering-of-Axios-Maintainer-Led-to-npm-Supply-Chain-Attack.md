---
layout: post
title:  "UNC1069 Social Engineering of Axios Maintainer Led to npm Supply Chain Attack"
date:   2026-04-03 12:46:29 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Axios 套件供應鏈攻擊：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Social Engineering, Supply Chain Attack, Trojanized Package

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: Axios 套件維護者 Jason Saayman 被北韓威脅演員 UNC1069 透過高度針對性的社交工程攻擊，導致套件供應鏈被攻擊。
* **攻擊流程圖解**:
  1. 攻擊者偽裝成知名公司的創始人，邀請維護者加入一個假的 Slack 工作空間。
  2. 維護者加入後，攻擊者安排了一個假的 Microsoft Teams 會議，顯示了一個假的錯誤訊息，說明維護者的系統需要更新。
  3. 維護者更新後，攻擊者部署了一個遠端存取木馬，獲得了維護者的 npm 帳戶憑證。
  4. 攻擊者使用憑證發佈了兩個被植入惡意程式的 Axios 套件版本 (1.14.1 和 0.30.4)。
* **受影響元件**: Axios 套件版本 1.14.1 和 0.30.4。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 攻擊者需要有維護者的聯繫資訊和社交工程技巧。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 假的錯誤訊息
    error_message = "您的系統需要更新"
    
    # 假的更新連結
    update_link = "https://example.com/update"
    
    # 發送假的錯誤訊息和更新連結給維護者
    requests.post("https://example.com/error", data={"error_message": error_message, "update_link": update_link})
    
    ```
  *範例指令*: 使用 `curl` 發送假的錯誤訊息和更新連結給維護者。

```

bash
curl -X POST -H "Content-Type: application/json" -d '{"error_message": "您的系統需要更新", "update_link": "https://example.com/update"}' https://example.com/error

```
* **繞過技術**: 攻擊者可以使用社交工程技巧來繞過維護者的安全措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /update |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule axios_trojan {
      meta:
        description = "Axios 套件木馬"
        author = "Your Name"
      strings:
        $a = "https://example.com/update"
      condition:
        $a
    }
    
    ```
  或者是具體的 **SIEM 查詢語法** (Splunk/Elastic)。

```

sql
index=security sourcetype=web_traffic | search "https://example.com/update"

```
* **緩解措施**: 更新 Axios 套件版本，使用安全的更新連結，啟用安全的憑證驗證。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **Social Engineering (社交工程)**: 想像一個攻擊者假裝成一個信任的個體，例如一個公司的創始人，來欺騙維護者提供敏感資訊。技術上是指使用心理操縱和欺騙來獲得未經授權的存取權限。
* **Supply Chain Attack (供應鏈攻擊)**: 想像一個攻擊者攻擊一個軟件供應鏈中的弱點，例如一個套件維護者，來獲得未經授權的存取權限。技術上是指使用供應鏈中的弱點來攻擊目標系統。
* **Trojanized Package (被植入惡意程式的套件)**: 想像一個攻擊者將惡意程式植入一個套件中，例如 Axios 套件，來獲得未經授權的存取權限。技術上是指使用被植入惡意程式的套件來攻擊目標系統。

## 5. 🔗 參考文獻與延伸閱讀

- [原始報告](https://thehackernews.com/2026/04/unc1069-social-engineering-of-axios.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


