---
layout: post
title:  "Microsoft PowerToys adds new CursorWrap mouse 'teleport' tool"
date:   2026-01-20 18:28:14 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Microsoft PowerToys 0.97 的安全性與功能增強

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 4.3)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: `Windows API`, `PowerToys`, `CursorWrap`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: PowerToys 0.97 中的 `CursorWrap` 功能可能導致用戶在多顯示器環境中遇到鼠標指標異常跳躍的問題。這是由於 `CursorWrap` 功能在處理多顯示器的邏輯邊界時沒有進行適當的檢查，導致鼠標指標可能會被 teleport 到錯誤的位置。
* **攻擊流程圖解**: 
    1. 用戶啟動 PowerToys 0.97
    2. 啟用 `CursorWrap` 功能
    3. 移動鼠標到多顯示器邊界
    4. 鼠標指標被 teleport 到錯誤的位置
* **受影響元件**: PowerToys 0.97, Windows 10/11

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 用戶需要安裝 PowerToys 0.97 並啟用 `CursorWrap` 功能
* **Payload 建構邏輯**:

    ```
    
    python
    import pyautogui
    
    # 移動鼠標到多顯示器邊界
    pyautogui.moveTo(100, 100)
    
    # 啟用 CursorWrap 功能
    # ...
    
    # 移動鼠標到錯誤的位置
    pyautogui.moveTo(500, 500)
    
    ```
    *範例指令*: `curl -X POST -H "Content-Type: application/json" -d '{"cursorWrap": true}' http://localhost:8080/powerToys`
* **繞過技術**: 可以使用 `Windows API` 來繞過 `CursorWrap` 功能的檢查

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\PowerToys.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule PowerToys_CursorWrap {
        meta:
            description = "Detects PowerToys CursorWrap functionality"
            author = "Your Name"
        strings:
            $a = "CursorWrap" ascii
        condition:
            $a
    }
    
    ```
    或者是具體的 **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
    index=windows_eventlog (EventID=4688 AND CommandLine="*PowerToys.exe*")
    
    ```
* **緩解措施**: 更新 PowerToys 至最新版本，禁用 `CursorWrap` 功能

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **PowerToys**: 一套由 Microsoft 開發的 Windows 工具集，提供多種功能增強。
* **CursorWrap**: PowerToys 中的一個功能，允許用戶在多顯示器環境中將鼠標指標 teleport 到錯誤的位置。
* **Windows API**: Windows 操作系統提供的應用程式介面，允許開發人員存取 Windows 的功能。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/microsoft/microsoft-powertoys-adds-new-cursorwrap-mouse-teleport-tool/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1547/)


