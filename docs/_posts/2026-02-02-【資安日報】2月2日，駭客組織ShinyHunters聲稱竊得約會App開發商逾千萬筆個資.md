---
layout: post
title:  "【資安日報】2月2日，駭客組織ShinyHunters聲稱竊得約會App開發商逾千萬筆個資"
date:   2026-02-02 12:43:10 +0000
categories: [security]
severity: critical
---

# 🚨 解析 ShinyHunters 勒索軟體攻擊與 Match Group 資料洩露事件
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: 資料洩露與勒索軟體攻擊
> * **關鍵技術**: 勒索軟體、資料洩露、第三方平臺攻擊

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ShinyHunters 勒索軟體駭客組織藉由第三方平臺 AppsFlyer 取得 Match Group 用戶及員工資料，數量超過 1,000 萬筆。
* **攻擊流程圖解**: 
  1. ShinyHunters 獲得 AppsFlyer 的存取權限。
  2. 利用 AppsFlyer 的資料存取功能，取得 Match Group 的用戶及員工資料。
  3. 將資料壓縮成 1.7 GB 的檔案，並公布部分資料供買家檢驗。
* **受影響元件**: Match Group 的約會 App，包括 Tinder、OkCupid、Hinge 等。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要取得 AppsFlyer 的存取權限。
* **Payload 建構邏輯**:

    ```
    
    python
      import requests
    
      # AppsFlyer API 端點
      url = "https://api.appsflyer.com/v1/data"
    
      # 取得存取權限的 API 金鑰
      api_key = "YOUR_API_KEY"
    
      # 設定 API 請求的 header
      headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
      }
    
      # 設定 API 請求的資料
      data = {
        "app_id": "YOUR_APP_ID",
        "event": "install"
      }
    
      # 送出 API 請求
      response = requests.post(url, headers=headers, json=data)
    
      # 處理 API 回應
      if response.status_code == 200:
        print("取得資料成功")
      else:
        print("取得資料失敗")
    
    ```
* **繞過技術**: 可能使用代理伺服器或 VPN 來隱匿 IP 地址。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule ShinyHunters {
        meta:
          description = "ShinyHunters 勒索軟體攻擊"
          author = "YOUR_NAME"
        strings:
          $a = "ShinyHunters" ascii
          $b = "AppsFlyer" ascii
        condition:
          all of them
      }
    
    ```
* **緩解措施**: 
  1. 更新 AppsFlyer 的 API 金鑰。
  2. 啟用雙因素認證。
  3. 監控 API 請求的異常行為。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **勒索軟體 (Ransomware)**: 一種惡意軟體，會加密受害者的資料，並要求支付贖金以解密。
* **資料洩露 (Data Breach)**: 指的是敏感資料的未經授權存取或披露。
* **第三方平臺攻擊 (Third-Party Platform Attack)**: 指的是攻擊者利用第三方平臺的漏洞或弱點，來攻擊目標系統。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/173718)
- [MITRE ATT&CK](https://attack.mitre.org/)


