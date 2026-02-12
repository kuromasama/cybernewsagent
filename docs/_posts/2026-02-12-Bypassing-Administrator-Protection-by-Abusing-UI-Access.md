---
layout: post
title:  "Bypassing Administrator Protection by Abusing UI Access"
date:   2026-02-12 18:55:10 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Windows Administrator Protection 的 UI Access 繞過技術
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.0)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: UI Access, UAC, Windows Hooks, DLL Hijacking

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Windows 的 UI Access 功能允許低權限進程與高權限進程進行交互，但這個功能的實現存在漏洞，允許攻擊者繞過 Administrator Protection。
* **攻擊流程圖解**:
  1. 攻擊者創建一個具有 UI Access 標誌的進程。
  2. 進程與高權限進程進行交互，使用 Windows Hooks 或 DLL Hijacking 獲取任意代碼執行權限。
* **受影響元件**: Windows 10、Windows 11

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個具有 UI Access 標誌的進程。
* **Payload 建構邏輯**:

    ```
    
    python
    import ctypes
    import os
    
    # 創建一個具有 UI Access 標誌的進程
    def create_ui_access_process():
        # ...
        return process_handle
    
    # 獲取高權限進程的句柄
    def get_high_privilege_process_handle():
        # ...
        return process_handle
    
    # 使用 Windows Hooks 獲取任意代碼執行權限
    def exploit_windows_hooks(process_handle):
        # ...
        return
    
    # 創建一個具有 UI Access 標誌的進程
    ui_access_process_handle = create_ui_access_process()
    
    # 獲取高權限進程的句柄
    high_privilege_process_handle = get_high_privilege_process_handle()
    
    # 使用 Windows Hooks 獲取任意代碼執行權限
    exploit_windows_hooks(high_privilege_process_handle)
    
    ```
* **繞過技術**: 攻擊者可以使用 DLL Hijacking 獲取任意代碼執行權限。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ... | ... | ... | ... |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Windows_UI_Access_Exploit {
        meta:
            description = "Detects Windows UI Access exploit"
            author = "..."
        strings:
            $a = "CreateProcessAsUser"
            $b = "SetWindowsHookEx"
        condition:
            all of them
    }
    
    ```
* **緩解措施**: 更新 Windows 至最新版本，禁用 UI Access 功能。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **UI Access**: 一個允許低權限進程與高權限進程進行交互的功能。
* **UAC (User Account Control)**: 一個用於控制使用者權限的機制。
* **Windows Hooks**: 一個允許進程截獲其他進程的消息的機制。
* **DLL Hijacking**: 一種攻擊技術，允許攻擊者將惡意 DLL 加載到其他進程中。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1548/)


