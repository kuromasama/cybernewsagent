---
layout: post
title:  "Windows Kerberos驗證恐被DNS別名誘導，微軟補強HTTP服務防中繼攻擊"
date:   2026-01-24 06:23:11 +0000
categories: [security]
severity: high
---

# 🔥 解析 Windows Kerberos 中繼攻擊漏洞：利用 DNS CNAME 別名進行服務主體名稱建構

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數：8.1)
> * **受駭指標**: 中繼攻擊（Relay Attack）
> * **關鍵技術**: Kerberos、DNS CNAME 別名、服務主體名稱（SPN）建構

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Windows 在進行 Kerberos 服務驗證時，建構服務主體名稱（SPN）的流程會跟隨 DNS 回應的 CNAME 別名，並以別名主機名稱向票證授權服務 TGS 索取服務票證。這個過程中，如果攻擊者能夠攔截或竄改受害者的 DNS 查詢，就可能誘導用戶端替攻擊者指定的 SPN 索取票證。
* **攻擊流程圖解**:
  1. 攻擊者攔截或竄改受害者的 DNS 查詢。
  2. 攻擊者返回一個假的 DNS 回應，包含一個 CNAME 別名，指向攻擊者控制的主機。
  3. 受害者的用戶端使用假的 DNS 回應，建構一個假的 SPN。
  4. 受害者的用戶端使用假的 SPN 向 TGS 索取服務票證。
  5. 攻擊者攔截服務票證，並使用它來存取受害者的資源。
* **受影響元件**: Windows 10、Windows Server 2016、Windows Server 2019、Windows Server 2022。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要能夠攔截或竄改受害者的 DNS 查詢。
* **Payload 建構邏輯**:

    ```
    
    python
    import dns.resolver
    
    # 攻擊者控制的主機名稱
    attacker_hostname = "attacker.com"
    
    # 受害者的 DNS 查詢
    victim_dns_query = "example.com"
    
    # 攻擊者返回一個假的 DNS 回應
    fake_dns_response = dns.resolver.Answer(
        victim_dns_query,
        dns.rdata.CNAME(attacker_hostname)
    )
    
    # 攻擊者返回假的 DNS 回應
    dns.resolver.answer(victim_dns_query, fake_dns_response)
    
    ```
* **繞過技術**: 攻擊者可以使用 ARP 欺騙、DHCPv4 或 DHCPv6 投毒等手法來攔截或竄改受害者的 DNS 查詢。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | attacker.com | /etc/hosts |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule kerberos_relay_attack {
        meta:
            description = "Kerberos 中繼攻擊"
            author = "Blue Team"
        strings:
            $dns_query = "example.com"
            $cname_alias = "attacker.com"
        condition:
            $dns_query and $cname_alias
    }
    
    ```
* **緩解措施**: 更新 Windows 的 HTTP.sys 以支援通道綁定權杖 CBT，並設定服務端強制簽章或通道綁定權杖 CBT。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Kerberos**: 一種用於驗證和授權的安全協議。
* **DNS CNAME 別名**: 一種 DNS 記錄，將一個主機名稱別名到另一個主機名稱。
* **服務主體名稱 (SPN)**: 一種用於識別服務的名稱，包含服務類型、主機名稱和端口號。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/173567)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1557/)


