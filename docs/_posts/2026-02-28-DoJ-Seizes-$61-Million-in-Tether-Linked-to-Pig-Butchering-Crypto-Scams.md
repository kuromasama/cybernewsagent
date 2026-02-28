---
layout: post
title:  "DoJ Seizes $61 Million in Tether Linked to Pig Butchering Crypto Scams"
date:   2026-02-28 01:17:17 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Pig Butchering 騙局：從社會工程到加密貨幣洗錢

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.0)
> * **受駭指標**: Financial Fraud, Social Engineering
> * **關鍵技術**: Social Engineering, Cryptocurrency, Money Laundering

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Pig Butchering 騙局的根源在於社會工程和人類心理操控。攻擊者利用假的浪漫關係、投資機會等手段來欺騙受害者。
* **攻擊流程圖解**: 
    1. 攻擊者在社交媒體或約會平台上接觸受害者。
    2. 攻擊者建立信任關係，提供假的投資機會。
    3. 受害者投資加密貨幣。
    4. 攻擊者控制加密貨幣，進行洗錢。
* **受影響元件**: 所有使用加密貨幣的個人和組織。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有社交工程技巧和加密貨幣知識。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 假的投資平台
    url = "https://fake-investment-platform.com"
    
    # 受害者投資加密貨幣
    def invest_cryptocurrency(amount):
        # ...
        return requests.post(url, data={"amount": amount})
    
    # 攻擊者控制加密貨幣
    def control_cryptocurrency():
        # ...
        return requests.get(url)
    
    ```
    *範例指令*: `curl -X POST -H "Content-Type: application/json" -d '{"amount": 1000}' https://fake-investment-platform.com`
* **繞過技術**: 攻擊者可以使用 VPN、代理伺服器等技術來隱藏 IP 地址。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ... | ... | ... | ... |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule PigButchering {
        meta:
            description = "Pig Butchering 騙局偵測規則"
            author = "..."
        strings:
            $a = "https://fake-investment-platform.com"
        condition:
            $a
    }
    
    ```
    或者是具體的 SIEM 查詢語法 (Splunk/Elastic):

```

sql
index=security sourcetype=web_traffic | search "https://fake-investment-platform.com"

```
* **緩解措施**: 使用加密貨幣時要小心，驗證投資平台的合法性，避免提供個人資訊。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Social Engineering (社會工程)**: 想像一個攻擊者假裝成一個信任的個體，例如客服人員或朋友，來欺騙受害者。技術上是指利用人類心理弱點來取得受害者的信任和敏感資訊。
* **Cryptocurrency (加密貨幣)**: 一種使用加密技術來保證交易安全和控制新單位創建的數字貨幣。
* **Money Laundering (洗錢)**: 想像一個攻擊者將非法所得的金錢轉換成合法的資產。技術上是指使用各種手段來隱藏非法所得的來源和所有權。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/02/doj-seizes-61-million-in-tether-linked.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1056/)


