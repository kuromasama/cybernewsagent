---
layout: post
title:  "Popular WordPress Plugin Scripts Tampered to Plant Hidden Backdoors on Sites"
date:   2026-06-15 11:51:20 +0000
categories: [security]
severity: critical
---

# 🚨 解析 WordPress 推廣插件被劫持事件：技術分析與防禦策略
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: JavaScript Hijacking, CDN劫持, Web Shell

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者通過劫持WordPress推廣插件（PushEngage、OptinMonster和TrustPulse）的JavaScript文件，實現了對網站的遠程代碼執行。
* **攻擊流程圖解**:
  1. 攻擊者劫持插件的JavaScript文件。
  2. 網站管理員登錄網站，觸發JavaScript文件的加載。
  3. JavaScript文件創建一個新的管理員賬戶，並安裝一個隱藏的插件。
  4. 隱藏的插件開啟了一個遠程命令通道，允許攻擊者執行任意代碼。
* **受影響元件**: PushEngage、OptinMonster和TrustPulse插件的使用者。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得插件的JavaScript文件的寫入權限。
* **Payload 建構邏輯**:

    ```
    
    javascript
      // 示例Payload
      var payload = {
        "type": "script",
        "data": "https://example.com/malicious.js"
      };
    
    ```
  *範例指令*: 使用`curl`命令發送請求：

```

bash
  curl -X POST \
  https://example.com/wp-admin/admin-ajax.php \
  -H 'Content-Type: application/json' \
  -d '{"type": "script", "data": "https://example.com/malicious.js"}'

```
* **繞過技術**: 攻擊者可以使用CDN劫持技術來繞過網站的安全措施。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| IOC | 描述 |
| --- | --- |
| `https://tidio.cc` | 攻擊者控制的域名 |
| `84.201.6.54` | 攻擊者控制的IP地址 |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule malicious_js {
        meta:
          description = "偵測惡意JavaScript文件"
          author = "Your Name"
        strings:
          $js = "https://example.com/malicious.js"
        condition:
          $js
      }
    
    ```
  * 或者是具體的 **SIEM 查詢語法** (Splunk/Elastic)：

```

sql
  index=web_logs | search "https://example.com/malicious.js"

```
* **緩解措施**:
  1. 更新插件到最新版本。
  2. 檢查網站的JavaScript文件是否被修改。
  3. 使用CDN安全功能來防止劫持。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **JavaScript Hijacking**: 想像攻擊者可以控制網站的JavaScript文件，從而實現對網站的遠程代碼執行。技術上是指攻擊者通過劫持JavaScript文件來實現對網站的控制。
* **CDN劫持**: 想像攻擊者可以控制CDN的內容，從而實現對網站的遠程代碼執行。技術上是指攻擊者通過劫持CDN的內容來實現對網站的控制。
* **Web Shell**: 想像攻擊者可以通過一個隱藏的插件來實現對網站的遠程代碼執行。技術上是指攻擊者通過一個隱藏的插件來實現對網站的控制。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/popular-wordpress-plugin-scripts.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


