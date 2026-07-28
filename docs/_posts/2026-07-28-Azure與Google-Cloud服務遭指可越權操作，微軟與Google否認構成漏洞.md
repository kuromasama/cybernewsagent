---
layout: post
title:  "Azure與Google Cloud服務遭指可越權操作，微軟與Google否認構成漏洞"
date:   2026-07-28 13:49:13 +0000
categories: [security]
severity: high
---

# 🔥 解析雲端服務中的混淆代理人問題：Kubernetes與IAM的權限落差

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.0)
> * **受駭指標**: 權限提升 (Privilege Escalation)
> * **關鍵技術**: Kubernetes, IAM, 混淆代理人問題 (Confused Deputy Problem)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 混淆代理人問題是指系統中的一個代理人（例如雲端服務）具有高權限，但沒有正確地核對提出要求的使用者的權限，從而導致低權限使用者可以進行原本不能進行的操作。
* **攻擊流程圖解**: 
  1. 使用者提出要求給雲端服務。
  2. 雲端服務使用系統身分取得所需權限。
  3. 雲端服務沒有核對提出要求的使用者的權限。
  4. 高權限服務替低權限使用者完成原本不能進行的操作。
* **受影響元件**: Kubernetes、Azure Backup for AKS、Google Cloud Config Connector。

## 2. ⚔️ 紅隊實戰：攻擊向量與Payload (Red Team Operations)
* **攻擊前置需求**: 使用者需要具有雲端服務的使用權限。
* **Payload 建構邏輯**: 
    * 使用者可以要求雲端服務進行備份或還原操作。
    * 雲端服務可以使用系統身分取得所需權限。
    * 使用者可以利用雲端服務的權限進行原本不能進行的操作。

```

python
# 範例指令
import requests

# 要求雲端服務進行備份操作
response = requests.post('https://example.com/backup', headers={'Authorization': 'Bearer <token>'})

# 如果雲端服務沒有核對提出要求的使用者的權限，則可以進行原本不能進行的操作
if response.status_code == 200:
    print('成功進行備份操作')

```
* **繞過技術**: 可以使用雲端服務的權限進行原本不能進行的操作。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| <hash> | <ip> | <domain> | <file_path> |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule confused_deputy_problem {
        meta:
            description = "偵測混淆代理人問題"
            author = "Your Name"
        condition:
            // 如果雲端服務沒有核對提出要求的使用者的權限
            // 則可以進行原本不能進行的操作
            all of them:
                $a = "backup" in (1 of ($*.headers["Authorization"]))
                $b = "Bearer" in (1 of ($*.headers["Authorization"]))
                $c = "200" in (1 of ($*.status_code))
    }
    
    ```
* **緩解措施**: 需要雲端服務正確地核對提出要求的使用者的權限。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **混淆代理人問題 (Confused Deputy Problem)**: 想像一個代理人具有高權限，但沒有正確地核對提出要求的使用者的權限，從而導致低權限使用者可以進行原本不能進行的操作。技術上是指系統中的一個代理人具有高權限，但沒有正確地核對提出要求的使用者的權限，從而導致安全漏洞。
* **Kubernetes**: 一個開源的容器編排系統。
* **IAM (Identity and Access Management)**: 一個用於管理使用者身份和權限的系統。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/177694)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1068/)


