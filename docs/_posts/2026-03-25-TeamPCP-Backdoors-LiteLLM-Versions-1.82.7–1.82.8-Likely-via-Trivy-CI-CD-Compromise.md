---
layout: post
title:  "TeamPCP Backdoors LiteLLM Versions 1.82.7–1.82.8 Likely via Trivy CI/CD Compromise"
date:   2026-03-25 01:29:01 +0000
categories: [security]
severity: critical
---

# 🚨 解析 TeamPCP 對 litellm 的供應鏈攻擊：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: `Supply Chain Attack`, `Kubernetes Lateral Movement`, `Systemd Backdoor`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: TeamPCP 利用了 litellm 的 CI/CD 工作流程中的 Trivy 工具，注入了惡意代碼到 litellm 的版本 1.82.7 和 1.82.8 中。
* **攻擊流程圖解**:
  1. TeamPCP 注入惡意代碼到 litellm 的版本中。
  2. 使用者安裝或更新 litellm 的版本。
  3. 惡意代碼被執行，收集使用者的認證資料和 Kubernetes 相關資訊。
  4. 惡意代碼將收集到的資料傳送到 TeamPCP 的命令和控制伺服器。
* **受影響元件**: litellm 版本 1.82.7 和 1.82.8，Kubernetes 集群。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 使用者需要安裝或更新 litellm 的版本，且需要有 Kubernetes 集群的存取權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import subprocess
    
    # 收集使用者的認證資料和 Kubernetes 相關資訊
    def collect_info():
        # ...
    
    # 將收集到的資料傳送到 TeamPCP 的命令和控制伺服器
    def send_info(info):
        # ...
    
    # 執行惡意代碼
    def execute_payload():
        collect_info()
        send_info(collect_info())
    
    execute_payload()
    
    ```
* **繞過技術**: TeamPCP 使用了多種技術來繞過安全防護，包括使用 `sysmon.service` 來建立持久的後門，和使用 `Kubernetes Lateral Movement` 來橫向移動到其他節點。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `1234567890abcdef` | `192.168.1.100` | `models.litellm.cloud` | `/usr/lib/litellm/proxy/proxy_server.py` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule litellm_malware {
        meta:
            description = "Detects litellm malware"
            author = "Your Name"
        strings:
            $a = "litellm/proxy/proxy_server.py"
        condition:
            $a at 0
    }
    
    ```
* **緩解措施**:
  1. 更新 litellm 到最新版本。
  2. 刪除惡意代碼和相關檔案。
  3. 更改 Kubernetes 集群的認證資料和相關設定。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 惡意攻擊者注入惡意代碼到軟體供應鏈中的某個環節，例如開發、測試或發佈過程中。
* **Kubernetes Lateral Movement (Kubernetes 橫向移動)**: 惡意攻擊者利用 Kubernetes 集群的特性，橫向移動到其他節點或容器中，進行進一步的攻擊。
* **Systemd Backdoor (Systemd 後門)**: 惡意攻擊者建立一個持久的後門，利用 systemd 服務來執行惡意代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/03/teampcp-backdoors-litellm-versions.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


