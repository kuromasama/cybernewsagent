---
layout: post
title:  "macOS權限提升攻擊鏈可暗中停用EDR、MDM代理程式"
date:   2026-07-01 02:49:11 +0000
categories: [security]
severity: high
---

# 🔥 解析 macOS 權限提升攻擊鏈：XPC 通訊機制漏洞利用
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: XPC 通訊機制、Code Directory Hash (CDHash)、Interface Builder (NIB) 檔案

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: macOS 的 XPC 通訊機制允許前端元件呼叫具備系統權限的背景程式，但這些背景程式通常只檢查連線來源的程式碼目錄雜湊 (CDHash) 來確認對方是否為合法元件。攻擊者可以修改應用程式封裝，植入惡意 Interface Builder (NIB) 檔案，使惡意程式得以冒充合法元件，向具有系統權限的背景程式發送指令。
* **攻擊流程圖解**:
  1. 攻擊者修改應用程式封裝，植入惡意 NIB 檔案。
  2. 攻擊者執行修改後的應用程式，macOS 核心將其 CDHash 保留在快取中。
  3. 攻擊者使用惡意 NIB 檔案冒充合法元件，向具有系統權限的背景程式發送指令。
* **受影響元件**: macOS、CrowdStrike Falcon Sensor、Iru Kandji Agent

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有權限修改應用程式封裝和植入惡意 NIB 檔案。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import subprocess
    
    # 修改應用程式封裝
    def modify_app_bundle(app_path, nib_file):
        # 將惡意 NIB 檔案植入應用程式封裝
        subprocess.run(['cp', nib_file, app_path + '/Contents/Resources'])
    
    # 執行修改後的應用程式
    def run_modified_app(app_path):
        subprocess.run([app_path + '/Contents/MacOS/' + os.path.basename(app_path)])
    
    # 使用惡意 NIB 檔案冒充合法元件
    def send_malicious_request(background_process):
        # 將惡意 NIB 檔案發送給具有系統權限的背景程式
        subprocess.run(['xpc', 'send', background_process, '-m', 'malicious_request'])
    
    ```
* **繞過技術**: 攻擊者可以使用各種繞過技術來避免被 EDR 或 WAF 偵測，例如使用加密通訊、隱藏惡意程式碼等。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /Applications/Example.app/Contents/Resources |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_nib_file {
        meta:
            description = "Detects malicious NIB files"
            author = "Your Name"
        strings:
            $nib_file = "malicious_nib_file.nib"
        condition:
            $nib_file at 0
    }
    
    ```
* **緩解措施**: 除了更新修補之外，還可以透過以下方式進行緩解：
  * 檢查應用程式封裝中的 NIB 檔案是否合法。
  * 使用 XPC 通訊機制的背景程式應該檢查連線來源的程式碼目錄雜湊 (CDHash) 來確認對方是否為合法元件。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **XPC 通訊機制 (XPC)**: XPC 是 macOS 的一種通訊機制，允許不同進程之間進行通訊。
* **Code Directory Hash (CDHash)**: CDHash 是 macOS 用於驗證應用程式合法性的雜湊值。
* **Interface Builder (NIB) 檔案**: NIB 檔案是 Interface Builder 儲存 UI 設計內容的檔案格式。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/176996)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1543/)


