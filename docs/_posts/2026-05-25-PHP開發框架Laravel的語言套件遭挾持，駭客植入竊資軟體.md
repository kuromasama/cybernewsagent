---
layout: post
title:  "PHP開發框架Laravel的語言套件遭挾持，駭客植入竊資軟體"
date:   2026-05-25 09:56:04 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Laravel Lang 套件惡意程式碼事件：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Info Leak 和 RCE
> * **關鍵技術**: `composer` 自動載入功能、Git 標籤竄改、正規表達式字典攻擊

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Laravel Lang 套件的 GitHub 儲存庫遭到入侵，攻擊者針對三個套件（`laravel-lang/lang`、`laravel-lang/attributes`、`laravel-lang/http-statuses`）發布指向帶有惡意程式碼版本的標籤。惡意程式碼利用 `composer` 自動載入功能執行，竊取憑證和敏感資訊。
* **攻擊流程圖解**:
  1. 攻擊者入侵 Laravel Lang 套件的 GitHub 儲存庫。
  2. 攻擊者發布指向帶有惡意程式碼版本的標籤。
  3. 使用 `composer` 自動載入功能執行惡意程式碼。
  4. 惡意程式碼利用正規表達式字典攻擊搜刮各種 API 金鑰和敏感資訊。
* **受影響元件**: Laravel Lang 套件的所有版本，包括 `laravel-lang/lang`、`laravel-lang/attributes`、`laravel-lang/http-statuses`。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要入侵 Laravel Lang 套件的 GitHub 儲存庫。
* **Payload 建構邏輯**:

    ```
    
    python
    import re
    
    # 定義正規表達式字典
    regex_dict = {
        'api_key': r'api_key=[a-zA-Z0-9_\-]+',
        'access_token': r'access_token=[a-zA-Z0-9_\-]+',
        # ...
    }
    
    # 搜刮敏感資訊
    def search_sensitive_info(file_path):
        with open(file_path, 'r') as f:
            content = f.read()
            for key, regex in regex_dict.items():
                matches = re.findall(regex, content)
                if matches:
                    print(f'Found {key}: {matches[0]}')
    
    # 執行搜刮
    search_sensitive_info('/path/to/file')
    
    ```
* **繞過技術**: 可以使用 WAF 繞過技巧，例如使用 Base64 編碼或其他編碼方式來隱藏惡意程式碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `abc123` | `192.168.1.100` | `example.com` | `/path/to/malicious/file` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_code {
        meta:
            description = "Detects malicious code"
            author = "Your Name"
        strings:
            $a = "api_key=[a-zA-Z0-9_\-]+"
            $b = "access_token=[a-zA-Z0-9_\-]+"
        condition:
            $a or $b
    }
    
    ```
* **緩解措施**: 更新 Laravel Lang 套件至最新版本，使用 `composer` 的 `--no-dev` 選項來禁用自動載入功能，設定 WAF 來阻止惡意流量。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Composer**: 一個 PHP 的套件管理工具，允許開發者輕鬆地安裝和管理套件。
* **Git 標籤 (Git Tag)**: Git 中的一個版本控制機制，允許開發者為特定的提交版本添加標籤。
* **正規表達式字典 (Regex Dictionary)**: 一個包含多個正規表達式的集合，用于搜刮和匹配特定的字符串模式。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/176082)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1056/)


