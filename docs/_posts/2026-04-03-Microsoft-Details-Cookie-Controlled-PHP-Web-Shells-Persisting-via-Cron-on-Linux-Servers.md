---
layout: post
title:  "Microsoft Details Cookie-Controlled PHP Web Shells Persisting via Cron on Linux Servers"
date:   2026-04-03 18:38:31 +0000
categories: [security]
severity: high
---

# 🔥 解析 Cookie 控制的 PHP Web Shell 攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Cookie 控制`, `PHP Web Shell`, `Obfuscation`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: PHP 的 `$_COOKIE` 超全局變數允許攻擊者通過 Cookie 值傳遞任意數據，從而實現遠程代碼執行。
* **攻擊流程圖解**:
  1. 攻擊者獲得受害者 Linux 伺服器的有效憑證或利用已知安全漏洞獲得初始訪問權。
  2. 攻擊者設置一個 cron 工作，定期調用一個 PHP 腳本，該腳本負責載入和執行一個被編碼的次要 payload。
  3. 攻擊者通過 HTTP 請求中的 Cookie 值傳遞指令，觸發 PHP 腳本執行惡意代碼。
* **受影響元件**: PHP 7.x 和 8.x 版本，Linux 伺服器。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 受害者 Linux 伺服器的有效憑證或已知安全漏洞。
* **Payload 建構邏輯**:

    ```
    
    php
      // 範例 Payload
      $cookie_value = $_COOKIE['malicious_cookie'];
      if ($cookie_value == 'trigger') {
        // 執行惡意代碼
        system('echo "Hello, World!" > /tmp/malicious_file.txt');
      }
    
    ```
 

```

bash
  # 範例指令
  curl -X GET \
  http://example.com/vulnerable.php \
  -H 'Cookie: malicious_cookie=trigger'

```
* **繞過技術**: 使用 obfuscation 技術隱藏惡意代碼，例如使用 base64 編碼或加密。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /tmp/malicious_file.txt |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule malicious_cookie {
        meta:
          description = "Detects malicious cookie values"
        strings:
          $cookie_value = "malicious_cookie=trigger"
        condition:
          $cookie_value
      }
    
    ```
 

```

spl
  index=web_logs sourcetype=http_access cookie="malicious_cookie=trigger"

```
* **緩解措施**:
  + 對 Linux 伺服器進行安全更新和修補。
  + 限制 cron 工作的執行權限。
  + 監控和限制 Cookie 值的傳遞。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Cookie 控制**: 想像 Cookie 值作為一個控制器，控制著 Web 應用程式的行為。技術上是指使用 Cookie 值傳遞指令，觸發惡意代碼的執行。
* **PHP Web Shell**: 一種使用 PHP 腳本實現的遠程代碼執行工具，允許攻擊者通過 Web 介面執行任意命令。
* **Obfuscation**: 一種隱藏惡意代碼的技術，例如使用 base64 編碼或加密，難以被偵測和分析。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/04/microsoft-details-cookie-controlled-php.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1210/)


