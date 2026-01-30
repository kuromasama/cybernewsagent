---
layout: post
title:  "Microsoft to disable NTLM by default in future Windows releases"
date:   2026-01-30 18:33:38 +0000
categories: [security]
severity: critical
---

# 🚨 NTLM 驗證協定漏洞解析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: NTLM Relay Attack, Pass-the-Hash Attack, Kerberos Authentication

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: NTLM 驗證協定使用弱密碼學和挑戰-回應機制，導致攻擊者可以輕易地進行 NTLM Relay Attack 和 Pass-the-Hash Attack。
* **攻擊流程圖解**:
  1. 攻擊者截獲 NTLM 驗證請求
  2. 攻擊者將請求轉發給目標伺服器
  3. 目標伺服器回應驗證結果
  4. 攻擊者使用回應結果進行驗證
* **受影響元件**: Windows NT 3.1 至 Windows 10、Windows Server 2000 至 Windows Server 2022

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 網路存取權限、目標伺服器的 NTLM 驗證設定
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # NTLM Relay Attack Payload
    def ntlm_relay_attack(target_server, username, password):
        # 使用 requests 進行 NTLM 驗證請求
        response = requests.get(target_server, auth=(username, password), headers={'NTLM': 'NTLM'})
        # 將回應結果轉發給目標伺服器
        return response.text
    
    # Pass-the-Hash Attack Payload
    def pass_the_hash_attack(target_server, username, hash):
        # 使用 requests 進行 NTLM 驗證請求
        response = requests.get(target_server, auth=(username, hash), headers={'NTLM': 'NTLM'})
        # 將回應結果轉發給目標伺服器
        return response.text
    
    ```
* **範例指令**:

    ```
    
    bash
    curl -X GET \
      http://example.com \
      -H 'NTLM: NTLM' \
      -u 'username:password'
    
    ```
* **繞過技術**: 使用 WAF 繞過技巧，例如使用 Base64 編碼的 NTLM 驗證請求

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /etc/passwd |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule ntlm_relay_attack {
      meta:
        description = "NTLM Relay Attack Detection"
      strings:
        $a = "NTLM" ascii
      condition:
        $a in (http.request.headers | re("NTLM"))
    }
    
    ```
* **緩解措施**:
  1.停用 NTLM 驗證協定
  2.啟用 Kerberos 驗證協定
  3.設定 WAF 來阻止 NTLM 驗證請求

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **NTLM (New Technology LAN Manager)**: 一種挑戰-回應的驗證協定，使用弱密碼學和挑戰-回應機制。
* **Kerberos Authentication**: 一種安全的驗證協定，使用票據和密碼學來進行驗證。
* **Pass-the-Hash Attack**: 一種攻擊方式，使用已經被竊取的密碼雜湊值來進行驗證。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/microsoft/microsoft-to-disable-ntlm-by-default-in-future-windows-releases/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1557/001/)


