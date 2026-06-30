---
layout: post
title:  "New BioShocking Attack Tricks AI Browsers Into Leaking User Credentials"
date:   2026-06-30 09:21:13 +0000
categories: [security]
severity: critical
---

# 🚨 解析 BioShocking 攻擊：AI 瀏覽器的間接提示注入漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Credentials Leak (憑證洩露)
> * **關鍵技術**: Indirect Prompt Injection (間接提示注入), Agent Mode (代理模式), Heap Spraying (堆疊噴射)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: BioShocking 攻擊的根源在於 AI 瀏覽器的代理模式（Agent Mode）中，瀏覽器無法區分普通內容和惡意命令。這是因為代理模式允許瀏覽器在用戶已登入的網站上執行操作，但同時也導致了安全性問題。
* **攻擊流程圖解**:
  1. 攻擊者創建一個惡意網頁，包含一個謎題或遊戲。
  2. 用戶訪問惡意網頁，AI 瀏覽器在代理模式下嘗試解決謎題。
  3. 謎題的設計使得 AI 瀏覽器接受錯誤的答案，從而執行惡意命令。
  4. 最終，AI 瀏覽器從用戶的 GitHub倉庫中提取 SSH 登入憑證，並將其傳遞給攻擊者。
* **受影響元件**: OpenAI 的 ChatGPT Atlas、Perplexity 的 Comet、Anthropic 的 Claude 瀏覽器擴展等。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個惡意網頁，並且用戶需要訪問該網頁。
* **Payload 建構邏輯**:

    ```
    
    python
    # 惡意網頁的 HTML 代碼
    <html>
      <body>
        <script>
          // 創建一個謎題或遊戲
          var puzzle = {
            question: "2 + 2 = ?",
            answer: "5"
          };
          
          // 執行惡意命令
          function executeMaliciousCommand() {
            // 從用戶的 GitHub 倉庫中提取 SSH 登入憑證
            var sshCredentials = getSSHCredentials();
            // 將憑證傳遞給攻擊者
            sendCredentialsToAttacker(sshCredentials);
          }
          
          // 解決謎題
          function solvePuzzle() {
            if (puzzle.answer === "5") {
              executeMaliciousCommand();
            }
          }
        </script>
      </body>
    </html>
    
    ```
* **繞過技術**: 攻擊者可以使用各種技術來繞過瀏覽器的安全機制，例如使用堆疊噴射（Heap Spraying）來執行惡意代碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /path/to/malicious/file |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule BioShocking_Attack {
      meta:
        description = "Detects BioShocking attack"
        author = "Your Name"
      strings:
        $puzzle_html = "<html>.*<script>.*var puzzle = {.*}</script>.*</html>"
      condition:
        $puzzle_html
    }
    
    ```
* **緩解措施**: 用戶可以通過以下方式來緩解 BioShocking 攻擊：
  1. 禁用 AI 瀏覽器的代理模式。
  2. 使用強密碼和兩步 驗證。
  3. 保持瀏覽器和操作系統更新。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Indirect Prompt Injection (間接提示注入)**: 惡意網頁通過創建一個謎題或遊戲，來間接地注入惡意命令到 AI 瀏覽器中。
* **Agent Mode (代理模式)**: AI 瀏覽器的代理模式允許瀏覽器在用戶已登入的網站上執行操作。
* **Heap Spraying (堆疊噴射)**: 一種攻擊技術，通過在堆疊中分配大量的內存來執行惡意代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/new-bioshocking-attack-tricks-ai.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


