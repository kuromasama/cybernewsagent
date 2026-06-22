---
layout: post
title:  "ShapedPlugin WordPress Pro Plugins Backdoored in Supply Chain Attack"
date:   2026-06-22 20:36:32 +0000
categories: [security]
severity: critical
---

# 🚨 解析 ShapedPlugin WordPress 插件供應鏈攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數: 10.0)
> * **受駭指標**: Remote Code Execution (RCE) 和資訊洩露
> * **關鍵技術**: Supply Chain Attack, Backdoor, Malware

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者竄改了 ShapedPlugin 的官方發佈渠道，將後門代碼注入到 Pro 版本的插件中。這些插件包括 Product Slider Pro for WooCommerce、Real Testimonials Pro 和 Smart Post Show Pro。
* **攻擊流程圖解**:
  1. 攻擊者竄改 ShapedPlugin 的官方發佈渠道。
  2. 受影響的插件版本被發佈到官方的 Easy Digital Downloads (EDD) 基礎設施。
  3. 使用者安裝或更新受影響的插件版本。
  4. 插件啟動後門代碼，從遠程伺服器下載和安裝 payload。
  5. Payload 啟動，開始收集和傳送敏感資訊。
* **受影響元件**: Product Slider Pro for WooCommerce (版本 3.5.4 之前)、Real Testimonials Pro (版本 3.2.5)、Smart Post Show Pro (版本 4.0.2 之前)

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要竄改 ShapedPlugin 的官方發佈渠道。
* **Payload 建構邏輯**:

    ```
    
    python
    # Payload 範例
    payload = {
        'action': 'install_plugin',
        'plugin': 'malicious_plugin',
        'version': '1.0'
    }
    
    ```
```

bash
# 使用 curl 下載和安裝 payload
curl -X POST \
  https://example.com/wp-admin/admin-ajax.php \
  -H 'Content-Type: application/json' \
  -d '{"action": "install_plugin", "plugin": "malicious_plugin", "version": "1.0"}'

```
* **繞過技術**: 攻擊者可以使用各種技術來繞過安全防護，例如使用加密的 payload 或利用已知的漏洞。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| IP | 194.76.217.28 |
| Domain | account.shapedplugin.com |
| File Path | wp-content/plugins/malicious_plugin/install-persistent.php |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_plugin {
        meta:
            description = "Malicious plugin detection"
            author = "Your Name"
        strings:
            $plugin_name = "malicious_plugin"
            $install_script = "install-persistent.php"
        condition:
            $plugin_name and $install_script
    }
    
    ```
```

snort
alert tcp any any -> any 80 (msg:"Malicious plugin detection"; content:"malicious_plugin"; sid:1000001;)

```
* **緩解措施**: 更新受影響的插件版本，重置所有密碼，撤銷和重新生成 2FA 秘密，審查管理員帳戶是否有未經授權的新增，檢查郵件插件配置是否有修改的 SMTP 認證。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Supply Chain Attack (供應鏈攻擊)**: 想像一個公司的供應鏈，如同一條長長的鏈子，攻擊者可以在任何一個環節進行攻擊。技術上是指攻擊者竄改或操縱供應鏈中的某個環節，例如軟件的開發、發佈或更新過程。
* **Backdoor (後門)**: 想像一個秘密的門，可以讓攻擊者在未經授權的情況下進入系統。技術上是指一種隱藏的入口，允許攻擊者遠程控制或存取系統。
* **Malware (惡意軟件)**: 想像一個壞人，可以在系統中進行各種惡意活動。技術上是指一種設計用於破壞或竊取系統資源的軟件。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/shapedplugin-wordpress-pro-plugins.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


