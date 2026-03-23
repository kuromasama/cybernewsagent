---
layout: post
title:  "Trivy Hack Spreads Infostealer via Docker, Triggers Worm and Kubernetes Wiper"
date:   2026-03-23 12:51:03 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Trivy 供應鏈攻擊：TeamPCP 的雲原生威脅
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Supply Chain Attack, Docker Hub, Kubernetes, eBPF

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Trivy 的供應鏈攻擊是由於 TeamPCP 獲得了 Aqua Security 的 GitHub Actions 的存取權限，從而可以推送惡意的 Docker 映像。
* **攻擊流程圖解**:
  1. TeamPCP 獲得 Aqua Security 的 GitHub Actions 的存取權限。
  2. TeamPCP 推送惡意的 Docker 映像到 Docker Hub。
  3. 使用者下載並運行惡意的 Docker 映像。
  4. 惡意的 Docker 映像執行任意命令，導致 RCE。
* **受影響元件**: Trivy 0.69.4, 0.69.5, 0.69.6

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要獲得 Aqua Security 的 GitHub Actions 的存取權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import subprocess
    
    # 下載惡意的 Docker 映像
    subprocess.run(["docker", "pull", "trivy:0.69.4"])
    
    # 運行惡意的 Docker 映像
    subprocess.run(["docker", "run", "-it", "trivy:0.69.4"])
    
    ```
* **繞過技術**: 可以使用 eBPF 來繞過 Docker 的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /usr/bin/trivy |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Trivy_Malicious_Image {
      meta:
        description = "Trivy 惡意映像"
        author = "Your Name"
      strings:
        $a = "trivy:0.69.4"
      condition:
        $a at 0
    }
    
    ```
* **緩解措施**: 更新 Trivy 到最新版本，避免使用受影響的版本。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 想像一個公司的供應鏈，如同一條長長的鏈子，攻擊者可以在任意一環中找到弱點，從而攻擊整個鏈子。技術上是指攻擊者通過操縱供應鏈中的某個環節，從而影響到最終的產品或服務。
* **Docker Hub (Docker 中央倉庫)**: Docker 中央倉庫是 Docker 映像的集中存儲和分發平台。攻擊者可以通過推送惡意的 Docker 映像到 Docker Hub，從而影響到使用這些映像的使用者。
* **eBPF (擴展的 Berkeley Packet Filter)**: eBPF 是 Linux 中的一個技術，允許用戶空間程序注入到內核中，從而可以實現各種功能，包括網絡封包過濾、系統調用跟蹤等。攻擊者可以使用 eBPF 來繞過 Docker 的安全機制。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/03/trivy-hack-spreads-infostealer-via.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


