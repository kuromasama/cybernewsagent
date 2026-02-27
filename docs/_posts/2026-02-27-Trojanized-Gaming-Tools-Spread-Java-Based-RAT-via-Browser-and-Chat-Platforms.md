---
layout: post
title:  "Trojanized Gaming Tools Spread Java-Based RAT via Browser and Chat Platforms"
date:   2026-02-27 12:41:47 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Java 遠端存取木馬 (RAT) 的技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: 遠端代碼執行 (RCE) 和敏感資訊洩露
> * **關鍵技術**: Java Archive (JAR) 文件、PowerShell、Living-off-the-land (LOTL) 二進制檔案

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: 攻擊者利用 Java 遠端存取木馬 (RAT) 的漏洞，通過下載和執行惡意的 Java Archive (JAR) 文件，從而實現遠端代碼執行和敏感資訊洩露。
* **攻擊流程圖解**:
	1. 使用者下載和執行惡意的 Java 遠端存取木馬 (RAT) 工具。
	2. RAT 工具下載和執行惡意的 Java Archive (JAR) 文件。
	3. JAR 文件利用 PowerShell 和 Living-off-the-land (LOTL) 二進制檔案實現遠端代碼執行和敏感資訊洩露。
* **受影響元件**: Java 8 和以上版本，Windows 10 和以上版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 使用者需要下載和執行惡意的 Java 遠端存取木馬 (RAT) 工具。
* **Payload 建構邏輯**:

    ```
    
    java
    // 惡意的 Java Archive (JAR) 文件
    public class MaliciousJAR {
        public static void main(String[] args) {
            // 利用 PowerShell 和 Living-off-the-land (LOTL) 二進制檔案實現遠端代碼執行和敏感資訊洩露
            Runtime.getRuntime().exec("powershell -Command \"& { Get-ChildItem -Path C:\\ -Recurse -Force }\"");
        }
    }
    
    ```
* **繞過技術**: 攻擊者可以利用 Living-off-the-land (LOTL) 二進制檔案和 PowerShell 的功能實現遠端代碼執行和敏感資訊洩露，從而繞過傳統的安全防禦措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:
	+ Hash: `1234567890abcdef`
	+ IP: `79.110.49.15`
	+ Domain: `example.com`
	+ File Path: `C:\\Windows\\Temp\\malicious.jar`
* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule MaliciousJAR {
        meta:
            description = "惡意的 Java Archive (JAR) 文件"
            author = "Blue Team"
        strings:
            $a = "powershell -Command"
        condition:
            $a
    }
    
    ```
* **緩解措施**: 使用者需要更新 Java 和 Windows 的安全補丁，同時設定 PowerShell 和 Living-off-the-land (LOTL) 二進制檔案的安全限制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **Java Archive (JAR) 文件**: 一種壓縮檔案格式，用于存儲 Java 程式和資源文件。
* **PowerShell**: 一種命令列 shell 和腳本語言，用于 Windows 系統管理和自動化。
* **Living-off-the-land (LOTL) 二進制檔案**: 一種利用現有系統二進制檔案實現攻擊的技術，從而繞過傳統的安全防禦措施。

## 5. 🔗 參考文獻與延伸閱讀

* [原始報告](https://thehackernews.com/2026/02/trojanized-gaming-tools-spread-java.html)
* [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


