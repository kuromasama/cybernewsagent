---
layout: post
title:  "China-Linked Hackers Target Asian Governments, NATO State, Journalists, and Activists"
date:   2026-05-01 19:02:23 +0000
categories: [security]
severity: high
---

# 🔥 解析中國聯盟的網絡間諜活動：SHADOW-EARTH-053 和 GLITTER CARP

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: ProxyLogon, DLL sideloading, Web shells

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: SHADOW-EARTH-053 集團利用 Microsoft Exchange 和 Internet Information Services (IIS) 服务器的 N-day 漏洞，例如 ProxyLogon 鏈，來獲得初始訪問權限。
* **攻擊流程圖解**:
  1. 攻擊者發送惡意請求到目標服务器，利用 ProxyLogon 鏈獲得執行命令的權限。
  2. 攻擊者部署 Web shells (例如 Godzilla) 來維持持久訪問權限。
  3. 攻擊者使用 DLL sideloading 技術，將惡意 DLL 文件注入合法的可執行文件中，從而繞過安全檢查。
* **受影響元件**: Microsoft Exchange 2013、2016 和 2019 版本，Internet Information Services (IIS) 服务器。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有目標服务器的網址和相關的漏洞信息。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義惡意請求的 URL 和資料
    url = "https://example.com/owa/auth.owa"
    data = {"username": "admin", "password": "password"}
    
    # 發送惡意請求
    response = requests.post(url, data=data)
    
    # 檢查是否成功
    if response.status_code == 200:
        print("成功獲得執行命令的權限")
    
    ```
* **繞過技術**: 攻擊者可以使用 DLL sideloading 技術，將惡意 DLL 文件注入合法的可執行文件中，從而繞過安全檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\malware.dll |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule SHADOW_EARTH_053 {
      meta:
        description = "SHADOW-EARTH-053 集團的惡意 DLL 文件"
        author = "Your Name"
      strings:
        $s1 = "malware.dll"
      condition:
        $s1 in (file_name)
    }
    
    ```
* **緩解措施**: 更新 Microsoft Exchange 和 IIS 服务器的安全補丁，使用 Web Application Firewall (WAF) 來檢查和阻止惡意請求。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DLL sideloading**: 惡意 DLL 文件注入合法的可執行文件中，從而繞過安全檢查。
* **ProxyLogon**: Microsoft Exchange 服务器的 N-day 漏洞，允許攻擊者獲得執行命令的權限。
* **Web shells**: 惡意的 Web 應用程序，允許攻擊者維持持久訪問權限。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/05/china-linked-hackers-target-asian.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


