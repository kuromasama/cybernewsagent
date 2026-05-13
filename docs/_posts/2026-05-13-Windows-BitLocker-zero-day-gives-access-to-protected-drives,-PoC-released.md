---
layout: post
title:  "Windows BitLocker zero-day gives access to protected drives, PoC released"
date:   2026-05-13 19:44:24 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Windows YellowKey 和 GreenPlasma 漏洞：BitLocker 繞過和特權提升

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: LPE (Local Privilege Escalation) 和 BitLocker 繞過
> * **關鍵技術**: NTFS 交易、Windows Recovery Environment、特權提升

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: YellowKey 漏洞是由於 Windows Recovery Environment (WinRE) 中的 NTFS 交易機制存在缺陷，允許攻擊者通過創建特殊的 FsTx 文件來繞過 BitLocker 加密。
* **攻擊流程圖解**:
  1. 攻擊者創建特殊的 FsTx 文件並將其放置在 USB 驅動器或 EFI 分區中。
  2. 攻擊者重新啟動系統並進入 WinRE。
  3. WinRE 啟動時，會自動檢查 FsTx 文件並執行其中的代碼。
  4. 代碼會刪除 `winpeshl.ini` 文件並啟動一個新的命令提示符。
* **受影響元件**: Windows 11 和 Windows Server 2022/2025。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有物理訪問權限或遠程桌面訪問權限。
* **Payload 建構邏輯**:

    ```
    
    python
    # 創建特殊的 FsTx 文件
    import os
    import struct
    
    # 定義 FsTx 文件結構
    class FsTx:
        def __init__(self, filename):
            self.filename = filename
            self.data = b''
    
        def add_data(self, data):
            self.data += data
    
        def save(self):
            with open(self.filename, 'wb') as f:
                f.write(self.data)
    
    # 創建 FsTx 文件
    fs_tx = FsTx('FsTx.bin')
    
    # 添加繞過 BitLocker 的代碼
    fs_tx.add_data(b'...')  # 代碼省略
    
    # 儲存 FsTx 文件
    fs_tx.save()
    
    ```
* **繞過技術**: 攻擊者可以使用此方法繞過 BitLocker 加密並獲得系統的控制權。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | `...` |
| IP | `...` |
| Domain | `...` |
| File Path | `...` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule YellowKey_Detection {
        meta:
            description = "YellowKey 漏洞偵測"
            author = "..."
        strings:
            $fs_tx = "FsTx.bin"
        condition:
            $fs_tx at 0
    }
    
    ```
* **緩解措施**: 更新 Windows 系統並啟用 BitLocker PIN 和 BIOS 密碼。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **NTFS 交易 (NTFS Transaction)**: NTFS 交易是一種用於確保文件系統的一致性和完整性的機制。它允許多個操作被視為一個單元，並在操作失敗時自動回滾。
* **Windows Recovery Environment (WinRE)**: WinRE 是 Windows 的一個恢復環境，允許用戶在系統無法啟動時進行恢復和維護操作。
* **特權提升 (Privilege Escalation)**: 特權提升是指攻擊者通過利用系統漏洞或其他方法來獲得更高的權限或控制權。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1068/)


