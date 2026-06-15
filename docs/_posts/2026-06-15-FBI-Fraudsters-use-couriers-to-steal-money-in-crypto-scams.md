---
layout: post
title:  "FBI: Fraudsters use couriers to steal money in crypto scams"
date:   2026-06-15 17:05:26 +0000
categories: [security]
severity: high
---

# 🔥 解析 Pig Butchering 騙局：從社會工程到金錢洗劫

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: Financial Loss
> * **關鍵技術**: Social Engineering, Phishing, Money Laundering

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Pig Butchering 騙局的根源在於攻擊者利用社會工程學手法建立信任關係，進而誘導受害者進行虛假投資。
* **攻擊流程圖解**:
  1. 攻擊者通過社交媒體、約會網站等平台與受害者建立聯繫。
  2. 攻擊者建立信任關係，提供虛假投資機會。
  3. 受害者進行投資，攻擊者將金錢轉移到自己的控制下。
  4. 攻擊者使用快遞員收取受害者的現金。
* **受影響元件**: 所有使用社交媒體、約會網站等平台的人員。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要建立信任關係，需要受害者的個人信息。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例 Payload
      payload = {
        "investment": "虛假投資機會",
        "password": "同意密碼",
        "serial_number": "美元鈔票序號"
      }
    
    ```
  *範例指令*: 使用 `curl` 發送虛假投資機會給受害者。

```

bash
  curl -X POST -H "Content-Type: application/json" -d '{"investment": "虛假投資機會"}' https://example.com/investment

```
* **繞過技術**: 攻擊者可以使用 VPN、代理等技術繞過受害者的安全設置。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| XXXX | 192.168.1.1 | example.com | /investment |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule PigButchering {
        meta:
          description = "Pig Butchering 騙局偵測"
        strings:
          $a = "虛假投資機會"
        condition:
          $a
      }
    
    ```
  或者是具體的 **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
      index=security sourcetype=web_traffic | search "虛假投資機會"
    
    ```
* **緩解措施**: 使用安全的瀏覽器、更新操作系統和應用程序，避免使用公共 Wi-Fi 連接敏感網站。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Social Engineering (社會工程學)**: 想像一個攻擊者通過建立信任關係來誘導受害者進行某些行動。技術上是指攻擊者使用心理操縱手法來獲得受害者的信任。
* **Phishing (釣魚攻擊)**: 想像一個攻擊者通過發送虛假電子郵件或消息來誘導受害者提供敏感信息。技術上是指攻擊者使用電子郵件或消息來進行社會工程學攻擊。
* **Money Laundering (洗錢)**: 想像一個攻擊者通過將非法獲得的金錢轉移到合法的金融體系中。技術上是指攻擊者使用各種手法來隱藏金錢的來源和去向。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/fbi-fraudsters-use-couriers-to-steal-money-in-crypto-scams/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1566/)


