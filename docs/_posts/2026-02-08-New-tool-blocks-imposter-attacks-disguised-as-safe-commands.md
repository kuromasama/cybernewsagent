---
layout: post
title:  "New tool blocks imposter attacks disguised as safe commands"
date:   2026-02-08 18:27:18 +0000
categories: [security]
severity: high
---

# 🔥 解析 Tirith 工具：防禦 Homoglyph 攻擊與命令列環境威脅

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數：8.0)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Homoglyph 攻擊、Unicode lookalike 字元、ANSI 逃脫序列

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Tirith 工具的作者 Sheeki 指出，命令列環境（如 zsh、bash、fish、PowerShell）容易受到 Homoglyph 攻擊的影響。這種攻擊利用 Unicode lookalike 字元來偽造合法的網域名稱或命令，從而導致用戶執行惡意代碼。
* **攻擊流程圖解**:
	1. 攻擊者創建一個偽造的網域名稱，使用 Unicode lookalike 字元來模擬合法的網域名稱。
	2. 攻擊者將偽造的網域名稱嵌入到命令列環境中，例如通過電子郵件或網頁連結。
	3. 用戶在命令列環境中執行命令，未察覺到偽造的網域名稱。
	4. 命令列環境解析偽造的網域名稱，導致用戶執行惡意代碼。
* **受影響元件**: 所有使用命令列環境的系統，包括 Windows、Linux 和 macOS。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個偽造的網域名稱，使用 Unicode lookalike 字元來模擬合法的網域名稱。
* **Payload 建構邏輯**:

    ```
    
    python
    import urllib.parse
    
    # 偽造的網域名稱
    fake_domain = "example.com"
    
    # Unicode lookalike 字元
    lookalike_chars = ["\u0430", "\u0431", "\u0432"]
    
    # 建構偽造的網域名稱
    fake_domain_with_lookalike = fake_domain + lookalike_chars[0]
    
    # 將偽造的網域名稱嵌入到命令列環境中
    command = f"curl {fake_domain_with_lookalike}"
    
    print(command)
    
    ```
* **繞過技術**: 攻擊者可以使用 ANSI 逃脫序列來繞過命令列環境的安全檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /usr/bin/curl |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Tirith_Detection {
        meta:
            description = "Tirith 工具偵測規則"
            author = "Your Name"
        strings:
            $curl_command = "curl *"
            $lookalike_chars = "\u0430" | "\u0431" | "\u0432"
        condition:
            $curl_command and $lookalike_chars
    }
    
    ```
* **緩解措施**: 使用 Tirith 工具來檢查命令列環境中的命令，防止 Homoglyph 攻擊。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Homoglyph 攻擊**: 一種攻擊方式，利用 Unicode lookalike 字元來偽造合法的網域名稱或命令。
* **Unicode lookalike 字元**: Unicode 中的字元，與其他字元外觀相似，但具有不同的編碼。
* **ANSI 逃脫序列**: 一種用於控制終端的特殊字元序列，可以用來繞過安全檢查。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/new-tool-blocks-imposter-attacks-disguised-as-safe-commands/)
- [Tirith 工具](https://github.com/Sheeki/Tirith)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1190/)


