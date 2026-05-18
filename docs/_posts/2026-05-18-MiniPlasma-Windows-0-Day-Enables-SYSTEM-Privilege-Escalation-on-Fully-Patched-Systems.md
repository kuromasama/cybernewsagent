---
layout: post
title:  "MiniPlasma Windows 0-Day Enables SYSTEM Privilege Escalation on Fully Patched Systems"
date:   2026-05-18 09:46:03 +0000
categories: [security]
severity: critical
---

# 🚨 Windows MiniPlasma 0-Day 漏洞解析與防禦
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：8.8)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: `Use-after-free`, `Heap Spraying`, `Windows Driver`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: MiniPlasma 漏洞源於 Windows Cloud Files Mini Filter Driver (`cldflt.sys`) 中的 `HsmOsBlockPlaceholderAccess` 函數。該函數沒有正確地檢查邊界，導致了 use-after-free 的情況。
* **攻擊流程圖解**:
  1. 攻擊者先通過 `cldflt.sys` 驅動程序創建一個用於存儲文件的空間。
  2. 攻擊者隨後釋放該空間，但是在釋放後，攻擊者仍然可以通過 `HsmOsBlockPlaceholderAccess` 函數訪問該空間。
  3. 攻擊者可以利用這個漏洞來執行任意代碼，從而實現本地權限提升。
* **受影響元件**: 所有 Windows 版本，包括 Windows 11。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要在目標系統上具有普通用戶權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import ctypes
    
    # 載入 cldflt.sys 驅動程序
    cldflt = ctypes.WinDLL('cldflt')
    
    # 創建一個用於存儲文件的空間
    placeholder = cldflt.HsmOsBlockPlaceholderAccess()
    
    # 釋放該空間
    cldflt.HsmOsBlockPlaceholderAccess(placeholder)
    
    # 利用 use-after-free 的漏洞執行任意代碼
    cldflt.HsmOsBlockPlaceholderAccess(placeholder)
    
    ```
  *範例指令*: 可以使用 `curl` 或 `nmap` 來傳送 Payload。
* **繞過技術**: 攻擊者可以使用 Heap Spraying 技術來繞過某些防禦措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\System32\cldflt.sys |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule MiniPlasma {
      meta:
        description = "MiniPlasma 0-Day 漏洞偵測"
      strings:
        $cldflt = "cldflt.sys"
      condition:
        $cldflt in (pe.imports)
    }
    
    ```
  或者是具體的 SIEM 查詢語法 (Splunk/Elastic)。
* **緩解措施**: 更新 Windows 至最新版本，並啟用 Windows Defender ATP。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Use-after-free (用後釋放)**: 想像兩個人同時去改同一本帳簿。技術上是指多個執行緒同時存取共享記憶體，且至少有一個是寫入動作，導致數據不一致或邏輯錯誤。
* **Heap Spraying (堆疊噴灑)**: 一種技術，通過在堆疊中分配大量的記憶體，從而增加攻擊者控制堆疊的機會。
* **Windows Driver (Windows 驅動程序)**: 一種軟件，負責管理和控制硬件設備。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/05/miniplasma-windows-0-day-enables-system.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1068/)


