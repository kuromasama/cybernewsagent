---
layout: post
title:  "New NadMesh Botnet Hunts Exposed AI Services for Cloud Keys and Kubernetes Tokens"
date:   2026-07-17 18:56:53 +0000
categories: [security]
severity: critical
---

# 🚨 NadMesh Botnet 解析：雲端憑證與 AI 服務攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 與雲端憑證竊取
> * **關鍵技術**: `JSON-RPC`, `Kubernetes`, `Docker API`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: NadMesh Botnet 利用了 AI 服務和雲端憑證的漏洞，特別是針對未經驗證的 `JSON-RPC` 請求和 `Kubernetes` 叢集權限。
* **攻擊流程圖解**:
  1. `Shodan` 掃描器發現暴露的 AI 服務和雲端憑證。
  2. `NadMesh` Botnet 發送 `JSON-RPC` 請求以執行命令和竊取雲端憑證。
  3. `Kubernetes` 叢集權限被利用以存取和操控雲端資源。
* **受影響元件**: `ComfyUI`, `Ollama`, `n8n`, `Open WebUI`, `Langflow`, `Gradio` 等 AI 服務和 `Kubernetes` 叢集。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有暴露的 AI 服務和雲端憑證。
* **Payload 建構邏輯**:

    ```
    
    python
    import json
    import requests
    
    # 定義 JSON-RPC 請求
    payload = {
        "jsonrpc": "2.0",
        "method": "execute_command",
        "params": ["ls -l"],
        "id": 1
    }
    
    # 發送 JSON-RPC 請求
    response = requests.post("http://example.com/jsonrpc", json=payload)
    
    # 處理回應
    print(response.json())
    
    ```
* **繞過技術**: 可以使用 `Garble` 混淆和 `UPX` 壓縮來繞過防病毒軟件。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 31c69b3e12936abca770d430066f379ec1d997ec | 209.99.186.235 | cdnorigin.net | ~/.ssh/authorized_keys |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule NadMesh_Botnet {
      meta:
        description = "NadMesh Botnet Malware"
        author = "Your Name"
      strings:
        $a = "jsonrpc" ascii
        $b = "execute_command" ascii
      condition:
        $a and $b
    }
    
    ```
* **緩解措施**: 需要更新和修補 AI 服務和雲端憑證的漏洞，並設定防火牆和存取控制以限制未經驗證的請求。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **JSON-RPC (JSON 遠程程序呼叫)**: 一種輕量級的遠程程序呼叫協議，使用 JSON 格式進行數據交換。
* **Kubernetes (kube-ctl)**: 一種容器編排系統，提供自動化的容器部署、擴展和管理功能。
* **Docker API (Docker 應用程式介面)**: 一種應用程式介面，提供對 Docker 容器的存取和控制功能。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


