---
layout: post
title:  "Closing the Door on Net-NTLMv1: Releasing Rainbow Tables to Accelerate Protocol Deprecation"
date:   2026-01-17 06:23:00 +0000
categories: [security]
---

# 🚨 解析 Net-NTLMv1 協議漏洞：利用 Rainbow Tables 進行密碼破解
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Authentication Coercion Attack
> * **關鍵技術**: Rainbow Tables, Net-NTLMv1, DES, Authentication Coercion

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Net-NTLMv1 協議的密碼破解漏洞源於其使用了 Data Encryption Standard (DES) 演算法，該演算法已被證明是不安全的。攻擊者可以利用 Rainbow Tables 進行密碼破解。
* **攻擊流程圖解**:
  1. 攻擊者獲得 Net-NTLMv1 雜湊值
  2. 攻擊者使用 Rainbow Tables 進行密碼破解
  3. 攻擊者獲得密碼雜湊值
  4. 攻擊者使用密碼雜湊值進行 DCSync 攻擊
* **受影響元件**: Windows 作業系統，特別是使用 Net-NTLMv1 協議進行驗證的系統

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得 Net-NTLMv1 雜湊值
* **Payload 建構邏輯**:

    ```
        
        python
        import hashlib
        
        # Net-NTLMv1 雜湊值
        ntlm_hash = "1122334455667788"
        
        # DES 演算法
        des_key = hashlib.md5(ntlm_hash.encode()).digest()
        
        # Rainbow Tables 查詢
        rainbow_table = ...
        
        
    
    ```
* **繞過技術**: 攻擊者可以使用 Responder 工具來獲得 Net-NTLMv1 雜湊值，並使用 PetitPotam 或 DFSCoerce 工具來進行 DCSync 攻擊

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
|---|---|---|---|
| 1122334455667788 | 192.168.1.100 | example.com | C:\Windows\System32\ntlm.dll |

* **偵測規則 (Detection Rules)**:

    ```
        
        yara
        rule NetNTLMv1_Detection {
          meta:
            description = "Detect Net-NTLMv1 authentication"
          strings:
            $a = "NTLMv1" ascii
          condition:
            $a
        }
        
        
    
    ```
* **緩解措施**: 禁用 Net-NTLMv1 協議，使用 NTLMv2 或 Kerberos 協議進行驗證

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Rainbow Tables**: 一種預先計算的表格，用于加速密碼破解過程。Rainbow Tables 通過預先計算常見的密碼雜湊值，然後存儲在表格中，以便快速查詢。
* **Net-NTLMv1**: 一種驗證協議，使用 DES 演算法進行密碼加密。Net-NTLMv1 已被證明是不安全的，應該禁用使用。
* **DCSync**: 一種攻擊技術，用于獲得 Domain Controller 的密碼雜湊值。DCSync 攻擊可以用於獲得 Domain Administrator 的權限。

## 5. 🔗 參考文獻與延伸閱讀
* [原始報告](https://cloud.google.com/blog/topics/threat-intelligence/net-ntlmv1-deprecation-rainbow-tables/)
* [MITRE ATT&CK](https://attack.mitre.org/techniques/T1110/)

