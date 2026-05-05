---
layout: post
title:  "Amazon SES increasingly abused in phishing to evade detection"
date:   2026-05-05 02:09:13 +0000
categories: [security]
severity: high
---

# 🔥 解析 Amazon Simple Email Service (SES) 被滥用進行釣魚攻擊的技術細節

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數：8.0)
> * **受駭指標**: Phishing and Email Spoofing
> * **關鍵技術**: AWS Identity and Access Management (IAM), Amazon SES, Phishing, Email Spoofing

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: AWS Identity and Access Management (IAM) 的存取金鑰被公開，導致攻擊者可以使用 Amazon SES 進行釣魚攻擊。
* **攻擊流程圖解**:
  1. 攻擊者在 GitHub、.ENV 文件、Docker 映像、備份和公開存取的 S3 儲存桶中找到 AWS IAM 的存取金鑰。
  2. 攻擊者使用 TruffleHog 公開源工具掃描並驗證存取金鑰的權限和電子郵件發送限制。
  3. 攻擊者使用 Amazon SES 發送釣魚電子郵件，包含惡意連結或附件。
* **受影響元件**: Amazon SES、AWS IAM

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: AWS IAM 的存取金鑰、Amazon SES 的使用權限
* **Payload 建構邏輯**:

    ```
    
    python
    import boto3
    
    ses = boto3.client('ses')
    
    # 定義電子郵件內容
    email_content = {
        'Source': 'example@example.com',
        'Destination': {
            'ToAddresses': ['victim@example.com']
        },
        'Message': {
            'Body': {
                'Text': {
                    'Data': '這是一個釣魚電子郵件'
                }
            }
        }
    }
    
    # 發送電子郵件
    response = ses.send_email(**email_content)
    
    ```
  *範例指令*: 使用 `curl` 發送電子郵件

```

bash
curl -X POST \
  https://email.us-west-2.amazonaws.com/ \
  -H 'Content-Type: application/json' \
  -d '{
        "Source": "example@example.com",
        "Destination": {
          "ToAddresses": ["victim@example.com"]
        },
        "Message": {
          "Body": {
            "Text": {
              "Data": "這是一個釣魚電子郵件"
            }
          }
        }
      }'

```
* **繞過技術**: 攻擊者可以使用 Amazon SES 的合法性來繞過電子郵件安全檢查

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| IP | 54.240.0.0/16 |
| Domain | amazonaws.com |
| File Path | /tmp/trufflehog.log |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Amazon_SES_Phishing {
      meta:
        description = "Amazon SES 釣魚攻擊"
        author = "Your Name"
      strings:
        $email_content = "這是一個釣魚電子郵件"
      condition:
        $email_content
    }
    
    ```
  * 或者是具體的 SIEM 查詢語法 (Splunk/Elastic)

```

sql
index=aws_ses 

| search "Source=example@example.com"
| stats count as num_emails
| where num_emails > 10
```
* **緩解措施**:
  + 限制 IAM 權限
  + 啟用多因素驗證
  + 定期輪換存取金鑰
  + 應用 IP 基於存取限制和加密控制

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Amazon Simple Email Service (SES)**: 一個雲端電子郵件服務，允許開發人員發送和接收電子郵件。
* **AWS Identity and Access Management (IAM)**: 一個安全身份和存取管理服務，允許管理 AWS 資源的存取權限。
* **TruffleHog**: 一個公開源工具，用于掃描和驗證存取金鑰的權限和電子郵件發送限制。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/amazon-ses-increasingly-abused-in-phishing-to-evade-detection/)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1566/)


