---
layout: post
title:  "Popular LiteLLM PyPI package backdoored to steal credentials, auth tokens"
date:   2026-03-25 01:29:33 +0000
categories: [security]
severity: critical
---

# 🚨 解析 TeamPCP 對 LiteLLM 的供應鏈攻擊：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 與 Info Leak
> * **關鍵技術**: `Supply Chain Attack`, `Malicious Package`, `Infostealer`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: TeamPCP 攻擊團隊通過將惡意版本的 LiteLLM 包上傳到 PyPI，利用供應鏈攻擊的方式感染了數十萬台設備。惡意版本的 LiteLLM 包含了一個 base64 編碼的 payload，該 payload 在包被導入時執行。
* **攻擊流程圖解**:
  1. 使用者安裝惡意版本的 LiteLLM 包。
  2. 惡意包被導入，觸發 payload 的執行。
  3. Payload 部署 infostealer，竊取敏感數據。
  4. 敏感數據被加密並發送到攻擊者控制的域名。
* **受影響元件**: LiteLLM 1.82.7 和 1.82.8 版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要 PyPI 上的 LiteLLM 包的維護權限。
* **Payload 建構邏輯**:

    ```
    
    python
      import base64
    
      # base64 編碼的 payload
      payload = "your_base64_encoded_payload"
    
      # 解碼 payload
      decoded_payload = base64.b64decode(payload)
    
      # 執行 payload
      exec(decoded_payload)
    
    ```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用不同的編碼方式或壓縮算法來隱藏 payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `your_hash` | `your_ip` | `your_domain` | `your_file_path` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule LiteLLM_Malicious_Package {
        meta:
          description = "LiteLLM 惡意包偵測"
          author = "your_name"
        strings:
          $base64_payload = "your_base64_encoded_payload"
        condition:
          $base64_payload
      }
    
    ```
* **緩解措施**: 更新 LiteLLM 包到最新版本，旋轉所有密碼和敏感數據。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 惡意攻擊者通過攻擊供應鏈中的弱點，例如開源庫或軟件包，來感染最終使用者的系統。
* **Infostealer (信息竊取者)**: 一種惡意軟件，旨在竊取敏感數據，例如密碼、信用卡號碼等。
* **Base64 (基64編碼)**: 一種編碼方式，使用 64 個字符（A-Z、a-z、0-9、+、/）來表示二進制數據。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/popular-litellm-pypi-package-compromised-in-teampcp-supply-chain-attack/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1195/)


