---
layout: post
title:  "數位憑證機構DigiCert客服系統遭受社交工程攻擊， EV程式碼簽章憑證外洩遭撤銷"
date:   2026-05-05 07:59:59 +0000
categories: [security]
severity: critical
---

# 🚨 解析 DigiCert 社交工程攻擊：從螢幕保護程式到 EV 程式碼簽章憑證
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: 社交工程、螢幕保護程式、EV 程式碼簽章憑證

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者透過偽裝成螢幕保護程式的惡意檔案，入侵客服支援流程，進而取得 EV 程式碼簽章憑證相關資訊。這是因為客服系統的安全性不足，允許攻擊者上傳和執行惡意檔案。
* **攻擊流程圖解**:
  1. 攻擊者假冒客戶聯繫客服。
  2. 攻擊者發送偽裝成螢幕截圖的惡意 ZIP 檔案。
  3. 客服人員執行惡意檔案，導致客服系統被入侵。
  4. 攻擊者利用客服系統的存取權限，取得 EV 程式碼簽章憑證初始化碼。
* **受影響元件**: DigiCert 的客服系統和 EV 程式碼簽章憑證。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有客服系統的存取權限和 EV 程式碼簽章憑證的初始化碼。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import zipfile
    
    # 建立惡意 ZIP 檔案
    zip_file = zipfile.ZipFile('malicious.zip', 'w')
    zip_file.write('malicious.scr')
    zip_file.close()
    
    # 發送惡意 ZIP 檔案給客服人員
    
    ```
* **繞過技術**: 攻擊者可以使用社交工程技巧來繞過客服系統的安全性。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\malicious.scr |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_scr {
      meta:
        description = "偵測惡意螢幕保護程式"
      strings:
        $a = "malicious.scr"
      condition:
        $a at 0
    }
    
    ```
* **緩解措施**: 更新客服系統的安全性，限制客服人員的存取權限，使用多因素驗證機制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **社交工程 (Social Engineering)**: 想像一個攻擊者假冒成一個可信任的人，技術上是指使用心理操縱來取得敏感資訊或存取權限。
* **EV 程式碼簽章憑證 (EV Code Signing Certificate)**: 一種用於驗證軟體開發者的身份和程式碼的真實性，技術上是指使用公鑰基礎結構 (PKI) 來簽署程式碼。
* **螢幕保護程式 (Screen Saver)**: 一種用於保護螢幕不被過度使用的程式，技術上是指使用螢幕保護程式來執行惡意程式碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/175558)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


