---
layout: post
title:  "讓開發者更能掌控AI代理，Android Studio新增Agent技能與權限管理機制"
date:   2026-04-07 13:07:08 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Android Studio Panda 3 的 AI Agent 安全性與攻防技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS 分數：6.5)
> * **受駭指標**: LPE (Local Privilege Escalation)
> * **關鍵技術**: `Agent Skills`, `權限管理`, `沙箱模式`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Android Studio Panda 3 的 AI Agent 可能存在權限管理機制的漏洞，允許攻擊者繞過授權機制，讀取檔案、執行 shell 指令或存取網路。
* **攻擊流程圖解**: 
  1. 攻擊者創建一個惡意的 `.skills` 資料夾，包含一個 `SKILL.md` 檔案，定義了一個惡意的工作流程。
  2. 攻擊者將惡意的 `.skills` 資料夾放置在 Android Studio 專案根目錄下。
  3. AI Agent 自動使用惡意的工作流程，執行攻擊者定義的動作。
* **受影響元件**: Android Studio Panda 3，所有版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 Android Studio Panda 3 的使用權限。
* **Payload 建構邏輯**:

    ```
    
    python
      # 惡意的 SKILL.md 檔案內容
      {
        "name": "惡意工作流程",
        "description": "執行 shell 指令",
        "steps": [
          {
            "action": "execute",
            "command": "shell指令"
          }
        ]
      }
    
    ```
  *範例指令*: `curl -X POST -H "Content-Type: application/json" -d '{"name": "惡意工作流程", "description": "執行 shell 指令", "steps": [{"action": "execute", "command": "shell指令"}]}' http://localhost:8080/skills`
* **繞過技術**: 攻擊者可以使用 `總是允許` 規則，讓 AI Agent 永久授權惡意的工作流程。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**: 

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  | `.skills/SKILL.md` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule malicious_skill {
        meta:
          description = "惡意的 SKILL.md 檔案"
        strings:
          $a = "execute"
          $b = "shell指令"
        condition:
          $a and $b
      }
    
    ```
  * 或者是具體的 SIEM 查詢語法 (Splunk/Elastic)： `index=android_studio source=".skills/SKILL.md" | stats count by name`
* **緩解措施**: 
  1. 更新 Android Studio Panda 3 至最新版本。
  2. 啟用沙箱模式，限制 AI Agent 的權限。
  3. 定期審查 `.skills` 資料夾，刪除惡意的工作流程。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Agent Skills**: 惡意的工作流程，可以讓 AI Agent 執行攻擊者定義的動作。
* **權限管理**: Android Studio Panda 3 的權限管理機制，允許攻擊者繞過授權機制。
* **沙箱模式**: 限制 AI Agent 的權限，防止惡意的工作流程執行。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/174888)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


