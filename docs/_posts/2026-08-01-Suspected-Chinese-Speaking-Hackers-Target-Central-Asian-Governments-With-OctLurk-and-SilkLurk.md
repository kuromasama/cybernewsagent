---
layout: post
title:  "Suspected Chinese-Speaking Hackers Target Central Asian Governments With OctLurk and SilkLurk"
date:   2026-08-01 02:06:47 +0000
categories: [security]
severity: critical
---

# 🚨 解析中國語言威脅演員的新型攻擊框架：OctLurk 和 SilkLurk

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 LPE (Local Privilege Escalation)
> * **關鍵技術**: OctLurk 和 SilkLurk 逆向工程、LurkProxy 的 SOCKS5 和透明代理、DLL side-loading

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: OctLurk 和 SilkLurk 的攻擊框架利用了目標系統的未知漏洞，利用 DLL side-loading 和 LurkProxy 進行命令和控制（C2）通信。
* **攻擊流程圖解**:
  1. 攻擊者利用未知漏洞獲得初始存取權。
  2. OctLurk 被注入記憶體並部署。
  3. LurkProxy 被啟動並建立 C2 連接。
  4. OctLurk 收集系統信息並加密後發送給 C2 伺服器。
  5. C2 伺服器下載和注入額外的插件以進行進一步的惡意操作。
* **受影響元件**: Windows 作業系統、未知版本的 DLL 文件。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有初始存取權、能夠注入 DLL 文件。
* **Payload 建構邏輯**:

    ```
    
    python
      # OctLurk 的基本結構
      class OctLurk:
          def __init__(self):
              self.c2_server = "dns.multitoconference[.]com"
              self.plugin_loader = PluginLoader()
    
          def collect_system_info(self):
              # 收集系統信息
              pass
    
          def encrypt_and_send(self, data):
              # 加密並發送數據給 C2 伺服器
              pass
    
      # LurkProxy 的基本結構
      class LurkProxy:
          def __init__(self):
              self.socks5_server = "154.196.162[.]76"
              self.transparent_proxy = False
    
          def start_proxy(self):
              # 啟動 SOCKS5 代理或透明代理
              pass
    
    ```
* **繞過技術**: 利用 DLL side-loading 和 LurkProxy 進行 C2 通信，繞過傳統的防火牆和入侵檢測系統。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  | 154.196.162[.]76 | dns.multitoconference[.]com |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule OctLurk {
          meta:
              description = "OctLurk Malware"
              author = "Your Name"
          strings:
              $a = "dns.multitoconference[.]com"
          condition:
              $a
      }
    
    ```
* **緩解措施**: 更新系統和應用程序、關閉不必要的端口、使用防火牆和入侵檢測系統。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DLL side-loading**: 一種攻擊技術，利用 Windows 的 DLL 加載機制，注入惡意 DLL 文件到目標程序中。
* **LurkProxy**: 一種代理工具，能夠進行 SOCKS5 和透明代理，繞過傳統的防火牆和入侵檢測系統。
* **C2 (Command and Control)**: 攻擊者用於控制和下達命令給受害者系統的通信機制。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/08/suspected-chinese-speaking-hackers.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


