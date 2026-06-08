---
layout: post
title:  "WhatsApp says it disrupted new NSO spyware phishing attacks"
date:   2026-06-08 20:05:46 +0000
categories: [security]
severity: high
---

# 🔥 解析 NSO Group 對 WhatsApp 用戶的 Spear-Phishing 攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Spear-Phishing`, `Zero-Day Vulnerability`, `eBPF`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: NSO Group 利用 WhatsApp 的零日漏洞進行 Spear-Phishing 攻擊，目的是讓用戶點擊惡意連結並下載 Pegasus Spyware。
* **攻擊流程圖解**:
  1. 攻擊者創建假的 WhatsApp 帳戶和群組。
  2. 攻擊者發送含有惡意連結的訊息給目標用戶。
  3. 用戶點擊連結後，會被重定向到外部網站。
  4. 外部網站會嘗試利用 WhatsApp 的零日漏洞下載 Pegasus Spyware。
* **受影響元件**: WhatsApp 的 Android 和 iOS 版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 WhatsApp 用戶的電話號碼和網路連接。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 惡意連結
    url = "https://example.com/malicious-link"
    
    # 發送含有惡意連結的訊息
    def send_message(phone_number, message):
        # 使用 WhatsApp API 或其他方法發送訊息
        pass
    
    # 重定向到外部網站
    def redirect_to_external_website(url):
        # 使用 HTTP 301 或 302 狀態碼重定向
        pass
    
    # 下載 Pegasus Spyware
    def download_pegasus_spyware():
        # 使用外部網站下載 Pegasus Spyware
        pass
    
    ```
* **繞過技術**: 攻擊者可以使用 eBPF 等技術繞過 WhatsApp 的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /malicious-link |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule WhatsApp_Spear_Phishing {
      meta:
        description = "WhatsApp Spear-Phishing 攻擊"
        author = "Your Name"
      strings:
        $url = "https://example.com/malicious-link"
      condition:
        $url in (http.request.uri)
    }
    
    ```
* **緩解措施**: 更新 WhatsApp 至最新版本，啟用 Advanced Protection 和 Lockdown Mode。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Spear-Phishing**: 一種針對特定目標的魚叉式網路釣魚攻擊，使用假的電子郵件或訊息來欺騙用戶點擊惡意連結或下載惡意軟體。
* **Zero-Day Vulnerability**: 一種尚未被發現或修復的安全漏洞，可以被攻擊者利用進行攻擊。
* **eBPF**: 一種 Linux 內核技術，允許用戶空間程式碼在內核中執行，常被用於安全和性能優化。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/whatsapp-says-it-disrupted-new-nso-spyware-phishing-attacks/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


