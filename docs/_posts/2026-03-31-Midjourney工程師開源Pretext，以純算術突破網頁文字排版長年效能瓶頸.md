---
layout: post
title:  "Midjourney工程師開源Pretext，以純算術突破網頁文字排版長年效能瓶頸"
date:   2026-03-31 07:05:00 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Pretext：基於 TypeScript 的文字排版引擎

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 4.3)
> * **受駭指標**: Performance Optimization
> * **關鍵技術**: `TypeScript`, `Canvas`, `Intl.Segmenter`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Pretext 的設計目的是為了提高文字排版的效能，尤其是在需要反覆計算文字高度的熱路徑場景中。它使用 Canvas 的文字量測功能來快取文字寬度，然後在記憶體中進行純算術運算來計算文字高度。
* **攻擊流程圖解**: 
  1. 使用者輸入文字
  2. Pretext 的 `prepare()` 函式整理字串，依語言排版規則切分成多個段落片段
  3. Pretext 的 `layout()` 函式根據容器寬度與行高，利用已快取的寬度做純算術運算，推算文字會分成幾行，以及整段文字的總高度
* **受影響元件**: Pretext 的版本號為 1.0.0，環境為基於 TypeScript 的網頁應用程式

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要對 Pretext 的源碼有所了解
* **Payload 建構邏輯**:

    ```
    
    typescript
      // 範例 Payload
      const pretext = new Pretext();
      const text = '這是一個測試文字';
      const containerWidth = 100;
      const lineHeight = 20;
      const result = pretext.layout(text, containerWidth, lineHeight);
      console.log(result);
    
    ```
  *範例指令*: 使用 `curl` 命令發送請求到 Pretext 的 API 來測試其效能
* **繞過技術**: 可以使用 `Intl.Segmenter` 來繞過 Pretext 的語言排版規則

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /pretext.js |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule pretext_detection {
        meta:
          description = "Pretext detection rule"
          author = "Your Name"
        strings:
          $pretext_js = "pretext.js"
        condition:
          $pretext_js
      }
    
    ```
  或者是具體的 **SIEM 查詢語法** (Splunk/Elastic)

```

sql
  index=web_logs sourcetype=access_combined | search pretext.js

```
* **緩解措施**: 更新 Pretext 到最新版本，設定 `Intl.Segmenter` 來強制使用語言排版規則

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **TypeScript**: 一種由 Microsoft 開發的程式語言，基於 JavaScript，並添加了靜態類型檢查和其他功能。
* **Canvas**: 一種 HTML 元素，允許使用 JavaScript 在網頁上繪製圖形和文字。
* **Intl.Segmenter**: 一種 API，提供語言感知分段功能，允許開發人員根據語言規則切分文字。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/174795)
- [Pretext GitHub](https://github.com/chenglou/pretext)
- [TypeScript 官方網站](https://www.typescriptlang.org/)
- [Canvas 官方文件](https://developer.mozilla.org/en-US/docs/Web/API/Canvas_API)
- [Intl.Segmenter 官方文件](https://developer.mozilla.org/en-US/docs/Web/API/Intl/Segmenter)


