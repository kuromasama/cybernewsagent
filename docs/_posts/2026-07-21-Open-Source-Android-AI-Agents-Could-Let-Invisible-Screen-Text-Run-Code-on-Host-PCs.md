---
layout: post
title:  "Open-Source Android AI Agents Could Let Invisible Screen Text Run Code on Host PCs"
date:   2026-07-21 13:21:51 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Android AI 代理漏洞：從無形文字到遠程命令執行
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: 遠程命令執行 (RCE)
> * **關鍵技術**: 無形文字注入、文件競爭、ADB Shell 命令執行

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Android AI 代理框架中的安全漏洞允許攻擊者通過無形文字注入和文件競爭來執行遠程命令。
* **攻擊流程圖解**:
  1. 攻擊者創建一個 Android 應用程序，可以在其他窗口上繪製並寫入共享存儲。
  2. 攻擊者使用無形文字注入技術將命令寫入共享存儲。
  3. AI 代理框架讀取共享存儲中的命令並執行。
* **受影響元件**: AppAgent、AppAgentX、Mobile-Agent-v3、Open-AutoGLM 和 MobA。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個 Android 應用程序可以在其他窗口上繪製並寫入共享存儲。
* **Payload 建構邏輯**:

    ```
    
    python
      # 示例 Payload
      payload = "calc.exe"
      # 將 Payload 寫入共享存儲
      with open("/sdcard/tmp.png", "w") as f:
          f.write(payload)
    
    ```
* **繞過技術**: 攻擊者可以使用文件競爭技術來繞過 AI 代理框架的安全檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /sdcard/tmp.png |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Android_Agent_RCE {
          meta:
              description = "Android AI 代理框架 RCE 攻擊"
              author = "Your Name"
          strings:
              $payload = "calc.exe"
          condition:
              $payload in (0..1000)
      }
    
    ```
* **緩解措施**: 更新 AI 代理框架至最新版本，並啟用安全檢查。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **無形文字注入 (Invisible Text Injection)**: 一種攻擊技術，通過在共享存儲中寫入無形文字來執行遠程命令。
* **文件競爭 (File Race Condition)**: 一種攻擊技術，通過在共享存儲中競爭文件鎖來繞過安全檢查。
* **ADB Shell 命令執行 (ADB Shell Command Execution)**: 一種攻擊技術，通過在 Android 设備上執行 ADB Shell 命令來執行遠程命令。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/open-source-android-ai-agents-could-let.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


