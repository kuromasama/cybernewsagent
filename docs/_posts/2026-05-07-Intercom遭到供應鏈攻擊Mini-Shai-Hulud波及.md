---
layout: post
title:  "Intercom遭到供應鏈攻擊Mini Shai-Hulud波及"
date:   2026-05-07 08:24:36 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Mini Shai-Hulud 供應鏈蠕蟲攻擊：技術細節與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和 Info Leak
> * **關鍵技術**: Deserialization, eBPF, Heap Spraying

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: NPM 套件 `intercom-client` 和 `intercom/intercom-php` 中的 Deserialization 漏洞，允許攻擊者執行任意程式碼。
* **攻擊流程圖解**: 
  1. 攻擊者上傳惡意的 JavaScript 檔案到 GitHub。
  2. 受害者安裝 `intercom-client` 或 `intercom/intercom-php` 套件。
  3. 套件下載並執行惡意的 JavaScript 檔案。
  4. 惡意程式碼收集 Kubernetes 和 Vault 的憑證並加密處理。
  5. 加密的憑證經由 GitHub API 流出。
* **受影響元件**: `intercom-client` 7.0.4 版和 `intercom/intercom-php` 的特定版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 GitHub 帳戶和上傳檔案的權限。
* **Payload 建構邏輯**:

    ```
    
    javascript
      // 範例 Payload
      const payload = {
        "type": "javascript",
        "code": "console.log('Hello, World!');"
      };
    
    ```
 

```

bash
  # 範例指令
  curl -X POST \
    https://api.github.com/repos/username/repo/contents/path/to/file \
    -H 'Authorization: Bearer YOUR_GITHUB_TOKEN' \
    -H 'Content-Type: application/json' \
    -d '{"message":"commit message","content":"base64 encoded payload"}'

```
* **繞過技術**: 攻擊者可以使用 eBPF 和 Heap Spraying 技術來繞過安全防護機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| XXXX | 192.168.1.100 | example.com | /path/to/malicious/file |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule malicious_javascript {
        meta:
          description = "Detects malicious JavaScript code"
          author = "Your Name"
        strings:
          $js_code = "console.log('Hello, World!');"
        condition:
          $js_code
      }
    
    ```
 

```

snort
  alert tcp any any -> any any (msg:"Malicious JavaScript code detected"; content:"console.log('Hello, World!');"; sid:1000001;)

```
* **緩解措施**: 更新 `intercom-client` 和 `intercom/intercom-php` 套件到最新版本，並設定 GitHub API 的安全性設定。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Deserialization (反序列化)**: 想像你收到一個打包好的禮物，需要拆開才能使用。技術上是指將資料從序列化的格式（如 JSON 或 XML）轉換回原始的物件或結構。
* **eBPF (Extended Berkeley Packet Filter)**: 想像你需要監控和控制網路流量。技術上是指一種 Linux 內核技術，允許用戶空間程式碼執行在內核空間。
* **Heap Spraying (堆疊噴灑)**: 想像你需要在記憶體中創建一個大型的緩衝區。技術上是指一種攻擊技術，通過在堆疊中分配大量的記憶體來繞過安全防護機制。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/175614)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


