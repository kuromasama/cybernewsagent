---
layout: post
title:  "24,650 Internet-Exposed BMCs Disclose IPMI Password Hashes Before Login"
date:   2026-07-28 19:13:20 +0000
categories: [security]
severity: critical
---

# 🚨 解析 IPMI v2.0 中的 CVE-2013-4786 漏洞：基於 BMC 的遠程管理風險

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數: 7.5)
> * **受駭指標**: 資訊洩露 (Information Leak)
> * **關鍵技術**: IPMI v2.0, HMAC-SHA1, Offline Password Cracking

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: IPMI v2.0 的設計中，BMC 在進行身份驗證時會返回一個包含 HMAC-SHA1 驗證碼的消息，該驗證碼是使用帳戶密碼和會話值計算得出的。這使得攻擊者可以在不需要進行多次登錄嘗試的情況下，對密碼進行離線猜測。
* **攻擊流程圖解**:
  1. 攻擊者發送一個 UDP 請求到 BMC 的 623 端口。
  2. BMC 返回一個包含 HMAC-SHA1 驗證碼的消息。
  3. 攻擊者使用密碼字典對密碼進行離線猜測。
* **受影響元件**: IPMI v2.0，包括 Dell、HPE 和 Supermicro 的 BMC。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 攻擊者需要能夠訪問 BMC 的 623 端口。
* **Payload 建構邏輯**:

    ```
    
    python
    import hashlib
    import hmac
    
    def calculate_hmac(password, session_values):
        # 使用 HMAC-SHA1 演算法計算驗證碼
        hmac_value = hmac.new(password.encode(), session_values.encode(), hashlib.sha1)
        return hmac_value.hexdigest()
    
    # 範例指令
    curl -X POST -H "Content-Type: application/json" -d '{"username": "admin", "password": "password"}' http://bmc_ip:623
    
    ```
* **繞過技術**: 攻擊者可以使用 GPU 加速的密碼破解工具來加速密碼猜測過程。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule IPMI_v2_0_Vulnerability {
      meta:
        description = "Detect IPMI v2.0 vulnerability"
        author = "Your Name"
      strings:
        $hmac_sha1 = { 68 6f 63 6b 65 79 }
      condition:
        $hmac_sha1 at 0
    }
    
    ```
 

```

snort
alert udp any any -> any 623 (msg:"IPMI v2.0 vulnerability detected"; sid:1000001; rev:1;)

```
* **緩解措施**:
  1. 封鎖 623 端口。
  2. 更新 BMC 韌體。
  3. 使用強密碼和密碼策略。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **IPMI (Intelligent Platform Management Interface)**: 一種用於遠程管理伺服器和其他設備的標準化接口。
* **HMAC-SHA1 (Keyed-Hash Message Authentication Code)**: 一種使用 SHA-1 演算法的密碼雜湊函數，用于驗證消息的完整性和真實性。
* **BMC (Baseboard Management Controller)**: 一種嵌入式管理控制器，用于監控和控制伺服器的硬件元件。

## 5. 🔗 參考文獻與延伸閱讀

* [原始報告](https://thehackernews.com/2026/07/24650-internet-exposed-bmcs-disclose.html)
* [MITRE ATT&CK](https://attack.mitre.org/techniques/T1215/)


