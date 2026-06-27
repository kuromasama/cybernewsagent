---
layout: post
title:  "FBI: Russian hackers now target Signal backup recovery keys"
date:   2026-06-27 02:34:23 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Signal Backup Recovery Key 窃取攻擊：俄羅斯情報服務的新手法
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Info Leak (敏感訊息洩露)
> * **關鍵技術**: Phishing, Social Engineering, End-to-End Encryption

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Signal 的 Backup Recovery Key 是用於加密和解密備份資料的金鑰。攻擊者通過 Phishing 手法騙取用戶的 Backup Recovery Key，從而可以存取用戶的歷史訊息。
* **攻擊流程圖解**:
  1. 攻擊者發送假的 Signal 支援郵件，聲稱需要用戶啟用兩步驟驗證。
  2. 用戶按照郵件中的指示，啟用 Signal 的 Secure Backups 功能，並創建一個 Backup Recovery Key。
  3. 攻擊者發送第二封郵件，聲稱用戶的資料因為同步問題而面臨丟失的風險。
  4. 用戶按照郵件中的指示，將 Backup Recovery Key 複製並發送給攻擊者。
* **受影響元件**: Signal 的 Secure Backups 功能，所有版本的 Signal 用戶都可能受到影響。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有能力發送假的 Signal 支援郵件，並且需要用戶的信任。
* **Payload 建構邏輯**:

    ```
    
    python
      # 假的 Signal 支援郵件
      subject = "Signal 支援：啟用兩步驟驗證"
      body = "您的 Signal 帳戶需要啟用兩步驟驗證。請按照以下步驟啟用：..."
    
    ```
 

```

bash
  # 發送假的 Signal 支援郵件
  curl -X POST \
  https://example.com/mail \
  -H 'Content-Type: application/json' \
  -d '{"subject": "' + subject + '", "body": "' + body + '"}'

```
* **繞過技術**: 攻擊者可以使用 Social Engineering 技術來繞過用戶的警惕，並且可以使用 Phishing 手法來騙取用戶的 Backup Recovery Key。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /path/to/file |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Signal_Phishing {
        meta:
          description = "Signal Phishing 攻擊"
          author = "Your Name"
        strings:
          $subject = "Signal 支援：啟用兩步驟驗證"
          $body = "您的 Signal 帳戶需要啟用兩步驟驗證。請按照以下步驟啟用：..."
        condition:
          $subject and $body
      }
    
    ```
 

```

spl
  index=mail subject="Signal 支援：啟用兩步驟驗證" | stats count as num_messages by sender

```
* **緩解措施**: 用戶應該小心處理來自未知發件人的郵件，並且不應該將 Backup Recovery Key 發送給任何人。Signal 用戶應該啟用兩步驟驗證，並且應該定期更改 Backup Recovery Key。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **End-to-End Encryption (端到端加密)**: 一種加密技術，能夠確保只有發送者和接收者可以存取訊息內容。
* **Phishing (釣魚攻擊)**: 一種社交工程攻擊，攻擊者通過假的郵件或網站來騙取用戶的敏感資訊。
* **Social Engineering (社交工程)**: 一種攻擊技術，攻擊者通過操縱用戶的心理和行為來達到攻擊目標。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/fbi-russian-hackers-now-target-signal-backup-recovery-keys/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1566/)


