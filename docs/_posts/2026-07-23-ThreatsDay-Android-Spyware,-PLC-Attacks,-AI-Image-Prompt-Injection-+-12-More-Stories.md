---
layout: post
title:  "ThreatsDay: Android Spyware, PLC Attacks, AI Image Prompt Injection + 12 More Stories"
date:   2026-07-23 19:04:02 +0000
categories: [security]
severity: critical
---

# 🚨 解析借用信任的威脅：從 GitHub 到 AI 模型的攻防技術
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Heap Spraying`, `Deserialization`, `eBPF`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 從程式碼層面解釋漏洞成因，例如在 GitHub 的 `ghe-support-bundle` 函數中沒有檢查邊界，導致任意檔案上傳。
* **攻擊流程圖解**:

    ```
    User Input -> ghe-support-bundle() -> Arbitrary File Upload -> RCE
    
    ```
* **受影響元件**: GitHub Enterprise Server (GHES) 版本 3.21.3 之前。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有 GitHub 帳戶和 GHES 實例的存取權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義 payload
    payload = {
        'file': open('malicious_file.txt', 'rb')
    }
    
    # 發送請求
    response = requests.post('https://github.example.com/ghe-support-bundle', files=payload)
    
    # 驗證結果
    if response.status_code == 200:
        print('Payload 上傳成功')
    
    ```
* **繞過技術**: 可以使用 `eBPF` 來繞過 Linux 的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `1234567890abcdef` | `192.168.1.100` | `github.example.com` | `/ghe-support-bundle` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule github_rce {
        meta:
            description = "GitHub RCE Detection"
            author = "Your Name"
        strings:
            $a = "ghe-support-bundle"
            $b = "malicious_file.txt"
        condition:
            all of them
    }
    
    ```
* **緩解措施**: 更新 GHES 至最新版本，限制檔案上傳權限。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **eBPF (Extended Berkeley Packet Filter)**: 一種 Linux 內核技術，允許用戶空間程式碼在內核中執行。
* **Deserialization**: 將序列化的資料轉換回原始物件的過程。
* **Heap Spraying**: 一種攻擊技術，通過在堆疊中分配大量的記憶體來繞過安全機制。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/threatsday-android-spyware-plc-attacks.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


