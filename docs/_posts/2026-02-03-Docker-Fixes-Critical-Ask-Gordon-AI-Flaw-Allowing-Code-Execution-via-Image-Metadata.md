---
layout: post
title:  "Docker Fixes Critical Ask Gordon AI Flaw Allowing Code Execution via Image Metadata"
date:   2026-02-03 18:46:45 +0000
categories: [security]
severity: critical
---

# 🚨 解析 DockerDash：Ask Gordon AI 的代碼執行與數據外洩漏洞

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: Meta-Context Injection, MCP Gateway, Docker Image

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Ask Gordon AI 沒有對 Docker Image 中的 metadata 進行充分的驗證，導致攻擊者可以通過嵌入惡意指令的 metadata 欄位來執行任意代碼。
* **攻擊流程圖解**:
  1. 攻擊者創建一個包含惡意 metadata 的 Docker Image。
  2. 當受害者查詢 Ask Gordon AI 有關該 Image 的信息時，Ask Gordon 會讀取 Image 的 metadata，包括惡意指令。
  3. Ask Gordon 將惡意指令轉發給 MCP Gateway。
  4. MCP Gateway 將惡意指令作為合法請求處理，並執行相關的 MCP 工具。
* **受影響元件**: Docker Desktop 和 Docker Command-Line Interface (CLI) 中的 Ask Gordon AI。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個包含惡意 metadata 的 Docker Image，並將其發布到 Docker Hub 或其他 Docker Image 倉庫中。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例惡意 metadata
      LABEL com.example.malicious="rm -rf /"
    
    ```
  攻擊者可以通過嵌入惡意指令的 metadata 欄位來執行任意代碼。
* **繞過技術**: 攻擊者可以使用各種技術來繞過安全防護，例如使用 Base64 編碼的惡意指令。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /usr/bin/malicious |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule malicious_metadata {
        meta:
          description = "Detects malicious metadata in Docker Images"
        strings:
          $a = "LABEL com.example.malicious"
        condition:
          $a
      }
    
    ```
 

```

snort
  alert tcp any any -> any any (msg:"Malicious metadata detected"; content:"LABEL com.example.malicious";)

```
* **緩解措施**: 更新 Docker Desktop 和 Docker CLI 至最新版本，禁用 Ask Gordon AI，或者使用第三方安全工具來掃描 Docker Image 中的惡意 metadata。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Meta-Context Injection**: 想像一個攻擊者可以通過嵌入惡意指令的 metadata 欄位來執行任意代碼。技術上是指攻擊者可以通過嵌入惡意指令的 metadata 欄位來執行任意代碼，從而繞過安全防護。
* **MCP Gateway**: MCP Gateway 是一個中間件層，負責處理 Ask Gordon AI 和 MCP 伺服器之間的請求。
* **Docker Image**: Docker Image 是一個包含應用程序代碼和依賴項的包，可以用於創建 Docker 容器。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/02/docker-fixes-critical-ask-gordon-ai.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


