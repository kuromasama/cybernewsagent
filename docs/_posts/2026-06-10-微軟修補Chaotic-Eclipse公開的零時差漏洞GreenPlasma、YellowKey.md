---
layout: post
title:  "微軟修補Chaotic Eclipse公開的零時差漏洞GreenPlasma、YellowKey"
date:   2026-06-10 02:46:00 +0000
categories: [security]
severity: high
---

# 🔥 解析微軟 6 月例行更新中的零時差漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數：7.8、6.8、7.5)
> * **受駭指標**: LPE (Local Privilege Escalation)、安全功能繞過、DoS (Denial of Service)
> * **關鍵技術**: Heap Spraying、Deserialization、HTTP/2 Bomb

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 
    + CVE-2026-45586 (GreenPlasma)：協作轉譯框架（Collaborative Translation Framework，CTFMON）中的權限提升漏洞，可能是由於沒有正確檢查用戶權限或邊界，導致攻擊者可以提升權限至 SYSTEM。
    + CVE-2026-50507 (YellowKey)：BitLocker 安全功能繞過漏洞，可能是由於實體接觸目標電腦時沒有正確驗證用戶權限，導致攻擊者可以繞過安全功能。
    + CVE-2026-49160 (HTTP/2 Bomb)：HTTP/2 通訊協定的 DoS 漏洞，可能是由於沒有正確處理 HTTP/2 的流量，導致攻擊者可以使服務器崩潰。
* **攻擊流程圖解**:
    + User Input -> CTFMON -> SYSTEM (CVE-2026-45586)
    + Physical Access -> BitLocker -> Security Bypass (CVE-2026-50507)
    + HTTP/2 Request -> Server -> DoS (CVE-2026-49160)
* **受影響元件**: 微軟 Windows 作業系統、BitLocker 安全功能、HTTP/2 通訊協定

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**:
    + CVE-2026-45586：需要有授權的用戶權限
    + CVE-2026-50507：需要實體接觸目標電腦
    + CVE-2026-49160：需要可以發送 HTTP/2 請求的網路位置
* **Payload 建構邏輯**:

    ```
    
    python
    # CVE-2026-45586
    import ctypes
    ctfmon = ctypes.windll.ctfmon
    ctfmon.CTFMON_Initialize()
    
    # CVE-2026-50507
    import os
    os.system("bitlocker.exe /bypass")
    
    # CVE-2026-49160
    import requests
    requests.post("https://example.com", headers={"Content-Type": "application/http"}, data="HTTP/2 Bomb")
    
    ```
    *範例指令*：使用 `curl` 發送 HTTP/2 請求

```

bash
curl -X POST \
  https://example.com \
  -H 'Content-Type: application/http' \
  -d 'HTTP/2 Bomb'

```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用 Base64 編碼或 URL 編碼來隱藏 Payload

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| XXXX | 192.168.1.100 | example.com | C:\Windows\ctfmon.exe |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule CVE_2026_45586 {
        meta:
            description = "CVE-2026-45586"
            author = "Your Name"
        strings:
            $s1 = "CTFMON_Initialize"
        condition:
            $s1
    }
    
    ```
    或者是具體的 SIEM 查詢語法 (Splunk/Elastic)

```

sql
index=security sourcetype=windows_security_eventlog EventID=4688 | stats count as num_events by user, computer_name

```
* **緩解措施**: 除了更新修補之外，還可以修改 Config 設定，例如修改 `nginx.conf` 設定或 Registry 修改

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Heap Spraying**: 想像一塊記憶體空間，攻擊者可以將惡意程式碼散佈在這塊空間中，技術上是指攻擊者可以將惡意程式碼寫入堆疊中，然後利用堆疊溢位或其他漏洞來執行惡意程式碼。
* **Deserialization**: 想像一個物件被序列化成字串，然後被反序列化回物件，技術上是指將資料從字串或其他格式轉換回物件或結構體。
* **HTTP/2 Bomb**: 想像一個 HTTP/2 請求被設計成可以使服務器崩潰，技術上是指攻擊者可以發送一個特殊的 HTTP/2 請求，然後使服務器因為處理請求而崩潰。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/176500)
- [MITRE ATT&CK](https://attack.mitre.org/)


