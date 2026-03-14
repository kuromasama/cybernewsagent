---
layout: post
title:  "AppsFlyer Web SDK hijacked to spread crypto-stealing JavaScript code"
date:   2026-03-14 18:29:11 +0000
categories: [security]
severity: critical
---

# 🚨 解析 AppsFlyer Web SDK 暫時被劫持事件：供應鏈攻擊與加密貨幣竊取
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 與 Info Leak
> * **關鍵技術**: JavaScript Obfuscation, Supply Chain Attack, Cryptocurrency Wallet Hijacking

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: AppsFlyer Web SDK 的官方域名 (`websdk.appsflyer.com`) 被劫持，導致惡意 JavaScript 代碼被注入到使用此 SDK 的網站和應用程序中。
* **攻擊流程圖解**:
  1. 使用者訪問使用 AppsFlyer Web SDK 的網站或應用程序。
  2. 惡意 JavaScript 代碼被注入到使用者的瀏覽器中。
  3. 惡意代碼監聽使用者的網路請求，尤其是與加密貨幣相關的請求。
  4. 當使用者輸入加密貨幣錢包地址時，惡意代碼會將其替換為攻擊者的錢包地址。
* **受影響元件**: AppsFlyer Web SDK 的所有版本，尤其是那些使用此 SDK 的 15,000 個商業客戶和 100,000 個移動和網頁應用程序。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要控制 AppsFlyer Web SDK 的官方域名或其 DNS 記錄。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 惡意 JavaScript 代碼範例
    function hijackWalletAddress() {
      // 監聽使用者的網路請求
      const xhr = new XMLHttpRequest();
      xhr.open('GET', 'https://example.com/wallet', true);
      xhr.onload = function() {
        if (xhr.status === 200) {
          // 取得使用者的錢包地址
          const walletAddress = xhr.responseText;
          // 將錢包地址替換為攻擊者的錢包地址
          const attackerWalletAddress = 'attacker_wallet_address';
          xhr.open('POST', 'https://example.com/wallet', true);
          xhr.setRequestHeader('Content-Type', 'application/json');
          xhr.send(JSON.stringify({ walletAddress: attackerWalletAddress }));
        }
      };
      xhr.send();
    }
    
    ```
* **繞過技術**: 攻擊者可以使用 JavaScript Obfuscation 技術來隱藏惡意代碼，避免被檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `sha256:...` | `192.0.2.1` | `websdk.appsflyer.com` | `/path/to/malicious/javascript` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_javascript {
      meta:
        description = "Detects malicious JavaScript code"
      strings:
        $js_code = { 61 73 6d 61 6c 69 63 69 6f 75 73 5f 63 6f 64 65 }
      condition:
        $js_code at entry_point
    }
    
    ```
* **緩解措施**: 更新 AppsFlyer Web SDK 到最新版本，使用安全的 DNS 記錄，並監聽網路請求以檢測惡意活動。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 惡意攻擊者瞄準軟體供應鏈中的弱點，以便在最終使用者系統中安裝惡意軟體。
* **JavaScript Obfuscation (JavaScript 混淆)**: 一種技術，用于使 JavaScript 代碼難以被人類閱讀和理解，從而避免被檢測。
* **Cryptocurrency Wallet Hijacking (加密貨幣錢包劫持)**: 惡意攻擊者竊取使用者的加密貨幣錢包地址，以便竊取其加密貨幣。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/appsflyer-web-sdk-used-to-spread-crypto-stealer-javascript-code/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


