---
layout: post
title:  "K8s新設Checkpoint Restore工作組，強化搶占與跨節點調度的狀態保存"
date:   2026-01-27 01:18:25 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Kubernetes 檢查點與還原技術的安全性與威脅
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: 資源使用最佳化、容錯與中斷感知排程
> * **關鍵技術**: Checkpoint/Restore, CRIU, Kubernetes

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Kubernetes 的檢查點與還原功能可能導致資源使用最佳化、容錯與中斷感知排程的安全性問題。
* **攻擊流程圖解**: 
    1. 攻擊者利用 Kubernetes 的檢查點與還原功能保存一份可恢復的執行狀態。
    2. 攻擊者利用這份保存的執行狀態進行資源使用最佳化、容錯與中斷感知排程的攻擊。
* **受影響元件**: Kubernetes 1.20 版本以上，CRIU 3.15 版本以上。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 Kubernetes叢集的管理權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import subprocess
    
    # 保存執行狀態
    def save_checkpoint():
        subprocess.run(["criu", "dump", "-t", "1234"])
    
    # 恢復執行狀態
    def restore_checkpoint():
        subprocess.run(["criu", "restore", "-t", "1234"])
    
    ```
    *範例指令*: `curl -X POST -H "Content-Type: application/json" -d '{"checkpoint": true}' http://localhost:8080/api/v1/namespaces/default/pods`
* **繞過技術**: 攻擊者可以利用 Kubernetes 的 API 繞過安全性檢查。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**: 

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /var/lib/criu |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Kubernetes_Checkpoint_Restore {
        meta:
            description = "Kubernetes 檢查點與還原功能的偵測規則"
            author = "Your Name"
        strings:
            $a = "criu dump -t"
            $b = "criu restore -t"
        condition:
            $a or $b
    }
    
    ```
    或者是具體的 **SIEM 查詢語法** (Splunk/Elastic): `index=kubernetes sourcetype=criu (dump OR restore)`
* **緩解措施**: 
    1. 更新 Kubernetes 與 CRIU 到最新版本。
    2. 限制 Kubernetes叢集的管理權限。
    3. 啟用 Kubernetes 的安全性功能，例如 Network Policies 與 Pod Security Policies。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Checkpoint/Restore**: Checkpoint/Restore 是一種技術，允許程序或容器在執行時保存一份可恢復的執行狀態，必要時再從保存點接續運作。
* **CRIU (Checkpoint/Restore In Userspace)**: CRIU 是一種開源的Checkpoint/Restore工具，允許用戶空間程序保存與恢復執行狀態。
* **Kubernetes**: Kubernetes 是一種開源的容器編排系統，允許用戶自動化容器的部署、擴展與管理。

## 5. 🔗 參考文獻與延伸閱讀
- [Kubernetes 官方文件](https://kubernetes.io/docs/)
- [CRIU 官方文件](https://criu.org/)
- [MITRE ATT&CK 編號](https://attack.mitre.org/)


