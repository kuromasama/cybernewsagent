---
layout: post
title:  "A Deep Dive into the GetProcessHandleFromHwnd API"
date:   2026-02-26 18:44:00 +0000
categories: [security]
severity: critical
---

# 🚨 解析 GetProcessHandleFromHwnd 功能的演變與安全性
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.0)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Windows Hook, UIPI (User Interface Privilege Isolation), Process Handle Duplication

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: GetProcessHandleFromHwnd 函數在 Windows 10 中被移動到 Win32k 核心模式，導致了安全性問題。該函數允許攻擊者在沒有適當權限的情況下取得目標進程的句柄。
* **攻擊流程圖解**: 
    1. 攻擊者創建一個具有 UI Access 權限的進程。
    2. 攻擊者使用 GetProcessHandleFromHwnd 函數取得目標進程的句柄。
    3. 攻擊者使用取得的句柄執行任意代碼。
* **受影響元件**: Windows 10 (版本 1803 及以上), Windows 11 (版本 24H2 以下)

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要具有 UI Access 權限的進程。
* **Payload 建構邏輯**:

    ```
    
    c
        // 取得目標進程的句柄
        HANDLE hProcess = GetProcessHandleFromHwnd(hWnd, PROCESS_DUP_HANDLE);
        // 執行任意代碼
        CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)shellcode, NULL, 0, NULL);
    
    ```
* **繞過技術**: 攻擊者可以使用 token stealing 攻擊來取得 UI Access 權限。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
        rule GetProcessHandleFromHwnd {
            meta:
                description = "Detect GetProcessHandleFromHwnd exploitation"
                author = "Your Name"
            strings:
                $shellcode = { 0x90 0x90 0x90 0x90 }
            condition:
                all of them
        }
    
    ```
* **緩解措施**: 更新 Windows 至最新版本，禁用 UI Access 權限，使用安全的代碼實踐。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **UIPI (User Interface Privilege Isolation)**: 一種 Windows 安全機制，限制低權限進程與高權限進程之間的交互。
* **Process Handle Duplication**: 一種 Windows 機制，允許進程複製另一個進程的句柄。
* **Token Stealing**: 一種攻擊技術，允許攻擊者竊取其他進程的 token。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://projectzero.google/2026/02/gphfh-deep-dive.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


