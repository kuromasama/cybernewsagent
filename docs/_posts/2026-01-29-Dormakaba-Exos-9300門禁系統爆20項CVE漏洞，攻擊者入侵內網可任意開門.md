---
layout: post
title:  "Dormakaba Exos 9300門禁系統爆20項CVE漏洞，攻擊者入侵內網可任意開門"
date:   2026-01-29 12:42:00 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Kaba Exos 9300 門禁系統弱點：利用與防禦
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: 預設缺乏身分驗證、硬編碼帳密、弱預設密碼、密碼衍生機制不當、路徑走訪與指令注入

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Kaba Exos 9300 門禁系統的管理介面缺乏適當的身分驗證機制，允許未經授權的存取。另外，系統使用硬編碼的帳密和金鑰，且預設密碼過於簡單，容易被猜測或破解。
* **攻擊流程圖解**:
  1. 攻擊者獲得目標環境的網路或存取硬體。
  2. 攻擊者利用預設缺乏身分驗證的管理介面存取系統。
  3. 攻擊者利用硬編碼帳密和金鑰進行授權。
  4. 攻擊者利用弱預設密碼或密碼衍生機制不當進行密碼猜測或破解。
  5. 攻擊者利用路徑走訪和指令注入進行任意門禁控制。
* **受影響元件**: Kaba Exos 9300 版本 4.4.0 之前的安裝環境。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得目標環境的網路或存取硬體。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義目標 URL 和預設帳密
    url = "https://example.com/exos9300/login"
    username = "admin"
    password = "default_password"
    
    # 建構登入請求
    login_request = requests.post(url, data={"username": username, "password": password})
    
    # 驗證登入結果
    if login_request.status_code == 200:
        print("登入成功")
    else:
        print("登入失敗")
    
    ```
* **範例指令**: 使用 `curl` 命令進行登入請求：

```

bash
curl -X POST -d "username=admin&password=default_password" https://example.com/exos9300/login

```
* **繞過技術**: 攻擊者可以利用 WAF 或 EDR 繞過技巧，例如使用代理伺服器或加密通訊。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /exos9300/login |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Exos9300_Login_Attempt {
        meta:
            description = "Detects Exos 9300 login attempts"
            author = "Your Name"
        strings:
            $login_url = "/exos9300/login"
        condition:
            $login_url in (http.request.uri)
    }
    
    ```
* **緩解措施**: 除了更新修補之外，還可以進行以下設定：
  * 啟用身分驗證機制。
  * 修改預設密碼和金鑰。
  * 限制管理介面存取權限。
  * 啟用 WAF 或 EDR 來防禦攻擊。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **預設缺乏身分驗證 (Default Lack of Authentication)**: 指系統預設沒有啟用身分驗證機制，允許未經授權的存取。
* **硬編碼帳密 (Hardcoded Credentials)**: 指系統使用硬編碼的帳密和金鑰，容易被猜測或破解。
* **路徑走訪 (Path Traversal)**: 指攻擊者可以利用系統的路徑走訪機制，存取未經授權的檔案或目錄。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/173667)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1190/)


