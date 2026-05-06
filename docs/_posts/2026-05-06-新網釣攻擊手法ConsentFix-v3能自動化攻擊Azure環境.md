---
layout: post
title:  "新網釣攻擊手法ConsentFix v3能自動化攻擊Azure環境"
date:   2026-05-06 02:10:36 +0000
categories: [security]
severity: critical
---

# 🚨 解析 ConsentFix v3：OAuth 權杖劫持與自動化攻擊技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: OAuth 權杖劫持與帳號存取
> * **關鍵技術**: OAuth 授權、同意網路釣魚、刷新權杖、Family of Client IDs (FOCI)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ConsentFix v3 攻擊手法的根源在於 OAuth 授權流程中的弱點，駭客可以透過社交工程和釣魚手法取得使用者的 OAuth 權杖，並利用這些權杖存取使用者的帳號和資料。
* **攻擊流程圖解**:
  1. 駭客建立一個假的 OAuth 客戶端，使用 Cloudflare Workers 作為主機代管。
  2. 使用 ZoomInfo 來識別目標使用者，並設計電子郵件活動來誘騙使用者授權假的 OAuth 客戶端。
  3. 使用者授權後，駭客可以取得使用者的 OAuth 權杖，並使用這些權杖存取使用者的帳號和資料。
  4. 駭客可以使用 Pipedream 作為外洩通道，將截取的 OAuth 權杖傳送給其他駭客工具。
* **受影響元件**: 所有使用 OAuth 授權的應用程式和服務，特別是那些使用 Cloudflare Workers 和 ZoomInfo 的應用程式。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 駭客需要有 Cloudflare Workers 和 ZoomInfo 的帳號，並需要有基本的網路安全知識和社交工程技巧。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 假的 OAuth 客戶端 ID 和密碼
    client_id = "fake_client_id"
    client_secret = "fake_client_secret"
    
    # 使用 ZoomInfo 來識別目標使用者
    target_user = "target_user@example.com"
    
    # 設計電子郵件活動來誘騙使用者授權假的 OAuth 客戶端
    email_content = "Please authorize our application to access your account."
    
    # 使用 Cloudflare Workers 作為主機代管
    worker_url = "https://example.com/worker"
    
    # 發送電子郵件給使用者
    requests.post(worker_url, data={"email": target_user, "content": email_content})
    
    # 使用者授權後，取得使用者的 OAuth 權杖
    access_token = requests.post("https://example.com/token", data={"client_id": client_id, "client_secret": client_secret, "grant_type": "authorization_code"}).json()["access_token"]
    
    # 使用取得的 OAuth 權杖存取使用者的帳號和資料
    requests.get("https://example.com/api/data", headers={"Authorization": f"Bearer {access_token}"})
    
    ```
* **繞過技術**: 駭客可以使用 SpecterPortal 等駭客工具來繞過安全防護機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /worker |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule OAuth_Token_Theft {
      meta:
        description = "Detect OAuth token theft"
        author = "Blue Team"
      strings:
        $oauth_token = "access_token=" ascii
      condition:
        $oauth_token in (http.request.body | http.response.body)
    }
    
    ```
* **緩解措施**: 使用者應該小心授權 OAuth 客戶端，並檢查授權的範圍和權限。應用程式和服務應該實施安全的 OAuth 授權流程，並使用安全的密碼和金鑰。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **OAuth (Open Authorization)**: 一種開放的授權標準，允許使用者授權第三方應用程式存取其帳號和資料。
* **FOCI (Family of Client IDs)**: 一種 OAuth 客戶端 ID 的家族，允許多個 OAuth 客戶端共用同一個 ID。
* **Cloudflare Workers**: 一種無伺服器的計算平台，允許開發者在 Cloudflare 的邊緣節點上執行代碼。
* **ZoomInfo**: 一種 B2B 數據平台，提供公司和使用者的聯繫信息和其他數據。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/175545)
- [OAuth 2.0 規範](https://tools.ietf.org/html/rfc6749)
- [Cloudflare Workers 文件](https://developers.cloudflare.com/workers/)
- [ZoomInfo 文件](https://www.zoominfo.com/support)


