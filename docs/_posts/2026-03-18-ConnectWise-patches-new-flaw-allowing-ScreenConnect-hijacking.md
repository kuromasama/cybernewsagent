---
layout: post
title:  "ConnectWise patches new flaw allowing ScreenConnect hijacking"
date:   2026-03-18 18:52:33 +0000
categories: [security]
severity: critical
---

# 🚨 解析 ScreenConnect 的加密簽名驗證漏洞：CVE-2026-3564
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Unauthorized Access and Privilege Escalation
> * **關鍵技術**: Cryptographic Signature Verification, ASP.NET Machine Keys, Deserialization

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: ScreenConnect 的加密簽名驗證機制存在漏洞，允許攻擊者竄改或生成有效的簽名，從而實現未經授權的存取和權限提升。
* **攻擊流程圖解**: 
  1. 攻擊者獲得 ScreenConnect 實例的機器金鑰（Machine Key）材料。
  2. 攻擊者使用機器金鑰材料生成或修改受保護的值。
  3. 攻擊者將修改的值提交給 ScreenConnect 實例。
  4. ScreenConnect 實例驗證簽名並接受修改的值。
* **受影響元件**: ScreenConnect 版本 26.1 之前的所有版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得 ScreenConnect 實例的機器金鑰材料。
* **Payload 建構邏輯**:

    ```
    
    python
    import hashlib
    import hmac
    
    # 機器金鑰材料
    machine_key = b"your_machine_key_here"
    
    # 要竄改的值
    value = b"your_value_here"
    
    # 生成簽名
    signature = hmac.new(machine_key, value, hashlib.sha256).digest()
    
    # 提交修改的值和簽名
    print(f"Value: {value.hex()}")
    print(f"Signature: {signature.hex()}")
    
    ```
* **繞過技術**: 攻擊者可以使用各種方法來繞過 ScreenConnect 的安全機制，例如使用已知的漏洞或弱點。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule ScreenConnect_Vulnerability {
      meta:
        description = "Detects potential exploitation of ScreenConnect vulnerability"
        author = "Your Name"
      strings:
        $signature = { 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f }
      condition:
        $signature at 0
    }
    
    ```
* **緩解措施**: 
  1. 升級 ScreenConnect 至版本 26.1 或更高。
  2. 加強機器金鑰材料的保護。
  3. 監控 ScreenConnect 實例的日誌和活動。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Cryptographic Signature Verification**: 一種使用加密技術來驗證數據完整性和真實性的方法。
* **ASP.NET Machine Keys**: ASP.NET 用於加密和解密數據的機器金鑰材料。
* **Deserialization**: 將序列化的數據轉換回原始形式的過程。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/connectwise-patches-new-flaw-allowing-screenconnect-hijacking/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


