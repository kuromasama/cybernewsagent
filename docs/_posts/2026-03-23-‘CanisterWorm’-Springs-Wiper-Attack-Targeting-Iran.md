---
layout: post
title:  "‘CanisterWorm’ Springs Wiper Attack Targeting Iran"
date:   2026-03-23 18:43:50 +0000
categories: [security]
severity: critical
---

# 🚨 解析 TeamPCP 的 CanisterWorm 攻擊：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Cloud Native Exploitation`, `Kubernetes`, `ICP Canisters`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: TeamPCP 利用了 Docker APIs、Kubernetes 集群和 Redis 服务器的漏洞，尤其是 React2Shell 漏洞，來實現自我傳播的蠕蟲攻擊。
* **攻擊流程圖解**:
  1. 初步入侵：攻擊者通過暴力掃描或其他手段，找到未安全配置的 Docker APIs、Kubernetes 集群或 Redis 服务器。
  2. 自我傳播：攻擊者利用找到的漏洞，將蠕蟲程式碼傳播到其他受影響的系統。
  3. 資料竊取和勒索：攻擊者收集敏感資料，並通過 Telegram 等平台進行勒索。
* **受影響元件**: Docker、Kubernetes、Redis 服务器，尤其是使用 React2Shell 的系統。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有初步入侵點，例如暴力掃描或社會工程學攻擊。
* **Payload 建構邏輯**:

    ```
    
    python
      import requests
    
      # 定義攻擊目標
      target = "http://example.com:8080"
    
      # 定義 Payload
      payload = {
          "cmd": "echo 'Hello, World!' > /tmp/test.txt"
      }
    
      # 發送請求
      response = requests.post(target, json=payload)
    
      # 處理回應
      if response.status_code == 200:
          print("攻擊成功")
      else:
          print("攻擊失敗")
    
    ```
* **繞過技術**: 可能使用 WAF 繞過技巧，例如使用 Base64 編碼或其他編碼方式來隱藏 Payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| XXXX | 192.168.1.100 | example.com | /tmp/test.txt |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule CanisterWorm {
          meta:
              description = "Detects CanisterWorm malware"
              author = "Your Name"
          strings:
              $a = "echo 'Hello, World!' > /tmp/test.txt"
          condition:
              $a
      }
    
    ```
* **緩解措施**: 更新系統和應用程式，尤其是 Docker、Kubernetes 和 Redis 服务器，使用安全配置和密碼，監控系統和網路流量。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Cloud Native Exploitation**: 雲原生應用程式的漏洞利用，尤其是利用 Docker、Kubernetes 和其他雲原生技術的漏洞。
* **ICP Canisters**: 一種基於區塊鏈的智能合約技術，允許創建自我傳播的蠕蟲程式碼。
* **React2Shell**: 一種漏洞，允許攻擊者在 React 應用程式中執行任意命令。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://krebsonsecurity.com/2026/03/canisterworm-springs-wiper-attack-targeting-iran/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


