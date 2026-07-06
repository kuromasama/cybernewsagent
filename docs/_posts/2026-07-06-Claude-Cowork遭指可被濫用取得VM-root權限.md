---
layout: post
title:  "Claude Cowork遭指可被濫用取得VM root權限"
date:   2026-07-06 15:18:54 +0000
categories: [security]
severity: high
---

# 🔥 解析 Claude Desktop 中的沙箱隔離機制漏洞：利用 DLL 載入與虛擬機器權限提升

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: LPE (Local Privilege Escalation) 與 RCE (Remote Code Execution)
> * **關鍵技術**: DLL 載入、Hyper-V 隔離、Ubuntu 虛擬機器、權限提升

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Claude Desktop 中的 CoworkVMService 沒有正確檢查 DLL 載入的合法性，導致攻擊者可以利用 DLL 載入漏洞在合法 Claude 程式的行程內執行惡意程式碼。
* **攻擊流程圖解**:
  1. 攻擊者先在 Windows 主機上取得程式執行能力。
  2. 攻擊者利用 DLL 載入漏洞，讓 Claude Desktop 載入惡意 DLL。
  3. 惡意 DLL 進行虛擬機器內的權限提升，取得 root 權限。
  4. 攻擊者可以在虛擬機器內執行命令，並對外連線。
* **受影響元件**: Claude Desktop for Windows，特別是 CoworkVMService。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要在 Windows 主機上取得程式執行能力。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例 Payload
      import ctypes
      import os
    
      # 載入惡意 DLL
      dll_path = "path/to/malicious.dll"
      ctypes.CDLL(dll_path)
    
      # 進行虛擬機器內的權限提升
      # ...
    
    ```
  *範例指令*: 使用 `curl` 下載惡意 DLL，並利用 `regsvr32` 注冊 DLL。
* **繞過技術**: 攻擊者可以利用 DLL 載入漏洞繞過 WAF 或 EDR 的檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ... | ... | ... | ... |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule malicious_dll {
        meta:
          description = "Malicious DLL"
          author = "Your Name"
        strings:
          $s1 = "malicious_code"
        condition:
          $s1
      }
    
    ```
  或者是具體的 **SIEM 查詢語法** (Splunk/Elastic)。
* **緩解措施**: 除了更新修補之外，企業可以限制能執行 Claude Desktop 的使用者或群組，並監看 `claude.exe` 是否從非系統目錄載入可疑 DLL。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DLL 載入 (DLL Loading)**: 想像兩個程式需要共享同一份函式庫。技術上是指程式動態載入 DLL 檔案，以使用其中的函式或變數。
* **Hyper-V 隔離 (Hyper-V Isolation)**: 想像兩個虛擬機器需要完全隔離。技術上是指使用 Hyper-V 技術創建虛擬機器，並限制其存取主機資源的能力。
* **Ubuntu 虛擬機器 (Ubuntu Virtual Machine)**: 想像一台完整的 Ubuntu 系統運行在虛擬機器中。技術上是指使用虛擬化技術創建一台完整的 Ubuntu 系統，並運行在虛擬機器中。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/177116)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1574/)


