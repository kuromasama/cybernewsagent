---
layout: post
title:  "Critical Rails Flaw Could Let Unauthenticated Attackers Read Server Files via Image Uploads"
date:   2026-07-29 19:02:07 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Ruby on Rails Active Storage 漏洞：任意檔案讀取與遠端代碼執行

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數: 9.5)
> * **受駭指標**: 任意檔案讀取與遠端代碼執行 (RCE)
> * **關鍵技術**: `libvips`, `Active Storage`, `Ruby on Rails`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 漏洞源於 `libvips` 的 `loaders` 和 `savers` 未能正確處理惡意輸入，導致 `Active Storage` 未能阻止這些操作，從而允許攻擊者讀取任意檔案。
* **攻擊流程圖解**:
  1. 攻擊者上傳一個精心設計的圖像檔案。
  2. `Active Storage` 使用 `libvips` 處理圖像檔案。
  3. `libvips` 的 `loaders` 和 `savers` 未能正確處理惡意輸入。
  4. 攻擊者可以讀取任意檔案，包括敏感的配置檔案和密碼。
* **受影響元件**: Ruby on Rails 7.0.0 至 7.2.3.1、8.0.0 至 8.0.5、8.1.0 至 8.1.3，以及使用 `libvips` 的 Active Storage。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要能夠上傳檔案到受影響的應用程式。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例 Payload
      import requests
    
      url = "https://example.com/upload"
      file = {"file": open("malicious_image.jpg", "rb")}
    
      response = requests.post(url, files=file)
    
      if response.status_code == 200:
          print("檔案上傳成功")
    
    ```
  * **範例指令**: 使用 `curl` 上傳檔案

```

bash
  curl -X POST \
  https://example.com/upload \
  -H 'Content-Type: application/octet-stream' \
  -T malicious_image.jpg

```
* **繞過技術**: 攻擊者可以使用各種技術來繞過防禦措施，例如使用不同的檔案格式或編碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule malicious_image {
          meta:
              description = "偵測惡意圖像檔案"
          strings:
              $a = "malicious_image.jpg"
          condition:
              $a
      }
    
    ```
  * **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
      index=web_logs | search "malicious_image.jpg"
    
    ```
* **緩解措施**: 更新 Ruby on Rails 至最新版本，設定 `libvips` 的 `block_untrusted` 選項為 `true`，並旋轉所有密碼和敏感配置檔案。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **libvips**: 一個用於圖像處理的庫，提供了各種圖像操作的功能。
* **Active Storage**: Ruby on Rails 中的一個模組，提供了檔案上傳和儲存的功能。
* **CVSS (Common Vulnerability Scoring System)**: 一個用於評估漏洞嚴重性的系統，提供了各種漏洞的評分和描述。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/critical-rails-flaw-could-let.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


