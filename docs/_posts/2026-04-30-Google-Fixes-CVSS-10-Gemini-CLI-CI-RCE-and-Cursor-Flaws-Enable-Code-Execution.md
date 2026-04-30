---
layout: post
title:  "Google Fixes CVSS 10 Gemini CLI CI RCE and Cursor Flaws Enable Code Execution"
date:   2026-04-30 08:08:45 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Google Gemini CLI 的遠程命令執行漏洞與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數: 10.0)
> * **受駭指標**: 遠程命令執行 (RCE)
> * **關鍵技術**: 命令執行、配置文件解析、沙盒繞過

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Gemini CLI 在 headless 模式下，自動信任工作目錄下的配置文件和環境變數，導致攻擊者可以通過配置文件注入惡意命令。
* **攻擊流程圖解**:
  1. 攻擊者提交一個包含惡意配置文件的 pull request。
  2. Gemini CLI 在 headless 模式下自動信任工作目錄下的配置文件。
  3. 惡意配置文件被載入，導致命令執行。
* **受影響元件**: 
  + `@google/gemini-cli` < 0.39.1
  + `@google/gemini-cli` < 0.40.0-preview.3
  + `google-github-actions/run-gemini-cli` < 0.1.22

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要提交一個包含惡意配置文件的 pull request。
* **Payload 建構邏輯**:

    ```
    
    json
    {
      "config": {
        "command": "malicious_command"
      }
    }
    
    ```
  *範例指令*: `curl -X POST -H "Content-Type: application/json" -d '{"config": {"command": "malicious_command"}}' https://example.com/gemini-cli`
* **繞過技術**: 攻擊者可以使用沙盒繞過技術，例如使用 `--yolo` 模式，來繞過安全檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| XXXX | 192.168.1.100 | example.com | /home/user/.gemini/config.json |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Gemini_CLI_RCE {
      meta:
        description = "Detects Gemini CLI RCE"
      strings:
        $config = { 28 29 30 31 32 33 34 35 36 37 38 39 }
      condition:
        $config at 0
    }
    
    ```
  * 或者是具體的 **SIEM 查詢語法** (Splunk/Elastic): `index=gemini-cli sourcetype=config.json command="malicious_command"`
* **緩解措施**: 
  + 更新 Gemini CLI 至最新版本。
  + 設定 `GEMINI_TRUST_WORKSPACE` 環境變數為 `false`。
  + 使用 `--yolo` 模式時，需要手動審核配置文件。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Race Condition (競爭危害)**: 想像兩個人同時去改同一本帳簿。技術上是指多個執行緒同時存取共享記憶體，且至少有一個是寫入動作，導致數據不一致或邏輯錯誤。
* **沙盒 (Sandbox)**: 一個隔離的環境，用于執行不信任的程式碼或配置文件。
* **配置文件 (Configuration File)**: 用于存儲應用程式配置信息的文件。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/04/google-fixes-cvss-10-gemini-cli-ci-rce.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


