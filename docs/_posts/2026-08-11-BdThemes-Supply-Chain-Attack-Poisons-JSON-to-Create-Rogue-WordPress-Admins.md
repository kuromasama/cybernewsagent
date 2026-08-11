---
layout: post
title:  "BdThemes Supply Chain Attack Poisons JSON to Create Rogue WordPress Admins"
date:   2026-08-11 06:53:45 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 WordPress Plugin 供應鏈攻擊：Biggopti 元件漏洞利用與防禦
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS 分數: 5.4)
> * **受駭指標**: XSS (Cross-Site Scripting) 與 RCE (Remote Code Execution)
> * **關鍵技術**: JSON 資料流污染、XSS、PHP Web Shell

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: BdThemes 的 Biggopti 元件中，存在一個 JSON 資料流解析漏洞，允許攻擊者注入任意的 Web 腳本，導致 XSS 攻擊。
* **攻擊流程圖解**:
  1. 攻擊者獲得 Biggopti 元件使用的 DigitalOcean Spaces bucket 的寫入權限。
  2. 攻擊者替換合法的 JSON 響應，注入惡意腳本。
  3. WordPress 管理員訪問受影響的插件時，惡意腳本被執行，創建新的管理員賬戶、上傳 Web Shell 等。
* **受影響元件**: BdThemes 的多個 WordPress 插件，包括 Element Pack Addons for Elementor、Live Copy Paste for Elementor 等。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要獲得 Biggopti 元件使用的 DigitalOcean Spaces bucket 的寫入權限。
* **Payload 建構邏輯**:

    ```
    
    javascript
      // 惡意 JSON 響應示例
      {
        "display_id": "<script>alert('XSS')</script>"
      }
    
    ```
 

```

bash
  # 使用 curl 上傳惡意 JSON 響應
  curl -X PUT \
    https://example.com/api-data-all-records \
    -H 'Content-Type: application/json' \
    -d '{"display_id": "<script>alert(\"XSS\")</script>"}'

```
* **繞過技術**: 攻擊者可以使用各種技術繞過安全防護，例如使用 Base64 編碼或其他編碼方式來隱藏惡意腳本。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| IP | 例: 192.0.2.1 |
| Domain | 例: example.com |
| File Path | 例: /wp-content/plugins/element-pack-addons-for-elementor/includes/biggopti.php |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule wordpress_biggopti_xss {
        meta:
          description = "Detects Biggopti XSS vulnerability"
          author = "Your Name"
        strings:
          $xss = "<script>"
        condition:
          $xss in (http.request.body | http.response.body)
      }
    
    ```
 

```

snort
  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"WordPress Biggopti XSS"; content:"<script>"; sid:1000001; rev:1;)

```
* **緩解措施**: 更新受影響的插件至最新版本，檢查 DigitalOcean Spaces bucket 的權限設定，確保只有授權的用戶可以寫入。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **XSS (Cross-Site Scripting)**: 惡意腳本注入攻擊，允許攻擊者在用戶的瀏覽器中執行任意的 Web 腳本。
* **JSON (JavaScript Object Notation)**: 一種輕量級的數據交換格式，常用於 Web API 的請求和響應中。
* **DigitalOcean Spaces**: 一種物件存儲服務，允許用戶存儲和提供大型文件和數據。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


