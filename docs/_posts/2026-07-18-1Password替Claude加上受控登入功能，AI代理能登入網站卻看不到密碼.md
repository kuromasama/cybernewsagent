---
layout: post
title:  "1Password替Claude加上受控登入功能，AI代理能登入網站卻看不到密碼"
date:   2026-07-18 07:38:45 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 1Password for Claude 的安全機制與潛在風險
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS 分數：6.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: `OAuth`, `JWT`, `浏覽器擴充功能`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 1Password for Claude 的安全機制是基於 OAuth 和 JWT 的，當 Claude 需要登入網站時，會向 1Password 提出憑證請求，1Password 桌面程式則顯示要求使用的登入項目及用途。使用者核准後，瀏覽器擴充功能會將使用者名稱、密碼或一次性驗證碼直接填入網站。
* **攻擊流程圖解**: 
  1. Claude 向 1Password 提出憑證請求
  2. 1Password 桌面程式顯示要求使用的登入項目及用途
  3. 使用者核准
  4. 瀏覽器擴充功能將使用者名稱、密碼或一次性驗證碼直接填入網站
* **受影響元件**: 1Password for Claude 的 Mac 版本

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: Claude 需要有權限存取 1Password 的憑證
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # Claude 向 1Password 提出憑證請求
    response = requests.post('https://example.com/1password/request', json={'username': 'username', 'password': 'password'})
    
    # 1Password 桌面程式顯示要求使用的登入項目及用途
    if response.status_code == 200:
        # 使用者核准
        approval_response = requests.post('https://example.com/1password/approve', json={'username': 'username', 'password': 'password'})
        if approval_response.status_code == 200:
            # 瀏覽器擴充功能將使用者名稱、密碼或一次性驗證碼直接填入網站
            fill_response = requests.post('https://example.com/1password/fill', json={'username': 'username', 'password': 'password'})
            if fill_response.status_code == 200:
                print('成功填入憑證')
            else:
                print('填入憑證失敗')
        else:
            print('使用者未核准')
    else:
        print('憑證請求失敗')
    
    ```
* **繞過技術**: 可以嘗試使用 CSRF 攻擊來繞過使用者核准步驟

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /1password/request |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule 1password_request {
      meta:
        description = "1Password Request"
        author = "Your Name"
      strings:
        $request = "https://example.com/1password/request"
      condition:
        $request
    }
    
    ```
* **緩解措施**: 可以設定 1Password 桌面程式只允許特定 IP 地址存取憑證

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OAuth**: OAuth 是一個開放標準的授權框架，允許用戶授權第三方應用程式存取其資源，而不需要提供密碼。
* **JWT**: JWT 是一個 JSON 物件，包含用戶的身份信息和授權信息，使用數字簽名確保其完整性和真實性。
* **浏覽器擴充功能**: 浏覽器擴充功能是一種可以擴充浏覽器功能的程式，通常使用 JavaScript 和 HTML 開發。

## 5. 🔗 參考文獻與延伸閱讀
- [1Password for Claude](https://1password.com/claude)
- [OAuth](https://oauth.net/2/)
- [JWT](https://jwt.io/)


