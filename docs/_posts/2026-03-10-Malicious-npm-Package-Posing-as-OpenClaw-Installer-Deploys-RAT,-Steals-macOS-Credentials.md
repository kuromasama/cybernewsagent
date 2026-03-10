---
layout: post
title:  "Malicious npm Package Posing as OpenClaw Installer Deploys RAT, Steals macOS Credentials"
date:   2026-03-10 01:21:03 +0000
categories: [security]
severity: critical
---

# 🚨 解析 npm 套件中嵌藏的遠端存取木馬：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 與 Info Leak
> * **關鍵技術**: Social Engineering, Encrypted Payload Delivery, Persistence, Data Exfiltration

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: 該 npm 套件 (`@openclaw-ai/openclawai`) 利用了 `postinstall` hook 來重新安裝自己，並透過 `bin` 欄位在使用者的 PATH 中添加可執行檔，從而達到遠端存取木馬的部署。
* **攻擊流程圖解**:
  1. 使用者安裝 npm 套件。
  2. `postinstall` hook 被觸發，重新安裝套件。
  3. `bin` 欄位添加可執行檔到使用者的 PATH 中。
  4. 使用者執行可執行檔，啟動遠端存取木馬。
* **受影響元件**: macOS、Node.js、npm

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 使用者需要安裝 npm 套件並執行可執行檔。
* **Payload 建構邏輯**:

    ```
    
    javascript
      // 範例 payload
      const payload = {
        "type": "script",
        "data": "https://trackpipe.dev/second-stage.js"
      };
    
    ```
 

```

bash
  # 範例指令
  curl -X POST -H "Content-Type: application/json" -d '{"type": "script", "data": "https://trackpipe.dev/second-stage.js"}' http://localhost:8080

```
* **繞過技術**: 使用 social engineering 技術來欺騙使用者輸入系統密碼，從而繞過 macOS 的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `1234567890abcdef` | `192.168.1.100` | `trackpipe.dev` | `/usr/local/bin/openclawai` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule openclawai {
        meta:
          description = "Detects openclawai malware"
          author = "Your Name"
        strings:
          $a = "openclawai" ascii
          $b = "trackpipe.dev" ascii
        condition:
          $a and $b
      }
    
    ```
 

```

snort
  alert tcp any any -> any 8080 (msg:"OpenClawai Malware"; content:"openclawai"; sid:1000001; rev:1;)

```
* **緩解措施**:
  1. 更新 npm 套件至最新版本。
  2. 刪除可執行檔 `/usr/local/bin/openclawai`。
  3. 修改 macOS 的安全設定，限制使用者權限。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **Social Engineering**: 想像一個攻擊者試圖欺騙使用者輸入敏感資訊。技術上是指使用心理操縱來欺騙使用者，從而達到攻擊者的目標。
* **Encrypted Payload Delivery**: 想像一個攻擊者試圖傳遞加密的 payload 到使用者的系統。技術上是指使用加密技術來保護 payload，從而避免被偵測。
* **Persistence**: 想像一個攻擊者試圖保持在使用者的系統中。技術上是指使用各種技術來保持攻擊者的存在，從而達到長期的攻擊目標。

## 5. 🔗 參考文獻與延伸閱讀

- [原始報告](https://thehackernews.com/2026/03/malicious-npm-package-posing-as.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1055/)


