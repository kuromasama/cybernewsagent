---
layout: post
title:  "Microsoft Exchange, Windows 11 hacked on second day of Pwn2Own"
date:   2026-05-16 02:15:15 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Pwn2Own Berlin 2026：零日漏洞利用與防禦技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.0-10.0)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Use-after-free, Integer Overflow, Deserialization

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 從程式碼層面解釋漏洞成因，例如：在 Microsoft Exchange 中，某個函數沒有檢查邊界，導致指針被釋放後重用，造成 use-after-free 漏洞。
* **攻擊流程圖解**:

    ```
    User Input -> malloc() -> free() -> use-after-free
    
    ```
* **受影響元件**: Microsoft Exchange、Windows 11、Red Hat Enterprise Linux for Workstations 等。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有網路存取權限和目標系統的版本號。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 建構 Payload
    payload = {
        'cmd': 'system',
        'args': ['whoami']
    }
    
    # 發送請求
    response = requests.post('https://example.com/vuln', json=payload)
    
    # 處理回應
    if response.status_code == 200:
        print('成功執行命令')
    else:
        print('失敗')
    
    ```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如：使用 Base64 編碼 Payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /vuln |
* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Microsoft_Exchange_Vuln {
        meta:
            description = "Microsoft Exchange Vuln"
            author = "Your Name"
        strings:
            $a = "cmd=system"
        condition:
            $a
    }
    
    ```
* **緩解措施**: 除了 Patch 之外的 Config 修改建議，例如：修改 `nginx.conf` 設定，增加安全頭。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Use-after-free (競爭危害)**: 想像兩個人同時去改同一本帳簿。技術上是指多個執行緒同時存取共享記憶體，且至少有一個是寫入動作，導致數據不一致或邏輯錯誤。
* **Integer Overflow (整數溢位)**: 當整數值超過最大限制時，會導致溢位，可能導致安全漏洞。
* **Deserialization (反序列化)**: 將資料從序列化格式轉換回原始格式，可能導致安全漏洞。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/pwn2own-day-two-hackers-demo-microsoft-exchange-windows-11-red-had-enterprise-linux-zero-days/)
- [MITRE ATT&CK](https://attack.mitre.org/)


