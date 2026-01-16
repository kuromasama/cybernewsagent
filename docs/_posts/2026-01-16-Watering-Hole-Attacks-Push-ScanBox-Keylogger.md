---
layout: post
title:  "Watering Hole Attacks Push ScanBox Keylogger"
date:   2026-01-16 13:15:41 +0000
categories: [security]
---

# 🚨 中國基礎威脅演員 TA423 啟動 ScanBox 攻擊框架針對澳洲和南海能源公司
## 1. 執行摘要
- **風險等級**：High
- **影響範圍**：澳洲國內組織和南海能源公司
- **事件簡述**：中國基礎威脅演員 TA423 啟動 ScanBox 攻擊框架，針對澳洲國內組織和南海能源公司，使用針對性郵件和水坑攻擊（Watering Hole Attack）進行攻擊。

## 2. 🔍 技術原理深度剖析
* ScanBox 攻擊框架是一種可定制和多功能的 JavaScript 基礎框架，用于進行隱蔽的偵查。
* **CVE 編號**：N/A
* **漏洞類型**：JavaScript Injection（JavaScript 注入）
* **MITRE ATT&CK 對應**：[T1190] Exploit Public-Facing Application（利用公共面向應用程序）
* **攻擊鏈路圖解**：User Input -> Filter Bypass -> JavaScript Code Execution -> Keylogger Functionality

## 3. ⚔️ 紅隊視角：攻擊模擬
* **前置條件**：攻擊者需要能夠控制一個網站，並且能夠將惡意的 JavaScript 代碼注入到該網站中。
* **攻擊向量**：攻擊者使用針對性郵件將受害者導向到一個被攻擊的網站，該網站包含惡意的 JavaScript 代碼。
* **模擬步驟 (Step-by-Step)**：
  1. 攻擊者創建一個針對性郵件，內容包含一個連結，指向一個被攻擊的網站。
  2. 受害者點擊連結，導向到被攻擊的網站。
  3. 被攻擊的網站注入惡意的 JavaScript 代碼，該代碼包含 ScanBox 攻擊框架。
  4. ScanBox 攻擊框架啟動，開始進行偵查和記錄受害者的鍵盤輸入。

## 4. 🛡️ 藍隊視角：防禦與緩解
* **IOCs (入侵指標)**：未提供
* **修補建議**：更新瀏覽器和操作系統到最新版本，確保所有的安全補丁都已經安裝。
* **臨時緩解措施 (Workaround)**：設定防火牆和 WAF 規則，阻止惡意的 JavaScript 代碼注入。
* **偵測規則建議**：在 SIEM 中監控所有的 JavaScript 代碼注入和異常行為。

## 5. 🔗 參考來源
- [原始報告](https://threatpost.com/watering-hole-attacks-push-scanbox-keylogger/180490/)




---
### 🔒 資安專家推薦
* **NordVPN**：保護您的網路足跡，防止駭客追蹤。[👉 點此查看優惠](https://nordvpn.com/)
* **Ledger 冷錢包**：保護加密資產的最佳實體錢包。[👉 了解更多](https://www.ledger.com/)
---

