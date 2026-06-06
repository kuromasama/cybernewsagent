---
layout: post
title:  "AI Agent Uncovers 21 Zero-Days in FFmpeg; Chrome Patches Record 429 Bugs"
date:   2026-06-06 08:26:10 +0000
categories: [security]
severity: critical
---

# 🚨 解析 AI 驅動的漏洞爆發：FFmpeg 和 Chrome 的安全挑戰
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS 9.6)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: Heap Overflow, Stack Overflow, AI 驅動的漏洞掃描

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: FFmpeg 中的 TS demuxer 和 VP9 decoder 存在堆疊和堆溢出漏洞，導致攻擊者可以執行任意代碼。Chrome 中的 ANGLE 圖形引擎存在越界讀寫漏洞，允許攻擊者逃逸沙盒並在主機上執行代碼。
* **攻擊流程圖解**:
  1. 攻擊者發送精心構造的媒體文件到 FFmpeg 或 Chrome。
  2. FFmpeg 或 Chrome 處理媒體文件時，觸發堆疊或堆溢出漏洞。
  3. 攻擊者控制堆疊或堆的內容，導致任意代碼執行。
* **受影響元件**: FFmpeg 1.5 million 行 C 代碼，Chrome 149 版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要知道 FFmpeg 或 Chrome 的版本和配置。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例 Payload
      payload = b'\x00\x01\x02\x03'  # 精心構造的媒體文件
      # 發送 Payload 到 FFmpeg 或 Chrome
      import requests
      response = requests.post('http://example.com/ffmpeg', data=payload)
    
    ```
  *範例指令*: 使用 `curl` 發送 Payload 到 FFmpeg 或 Chrome。

```

bash
  curl -X POST -H "Content-Type: application/octet-stream" -d "$payload" http://example.com/ffmpeg

```
* **繞過技術**: 攻擊者可以使用 WAF 繞過技巧，例如使用 Base64 編碼的 Payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /ffmpeg |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule FFmpeg_Exploit {
        meta:
          description = "FFmpeg 堆疊溢出漏洞"
          author = "Blue Team"
        strings:
          $a = { 00 01 02 03 }  // 精心構造的媒體文件
        condition:
          $a at entry0
      }
    
    ```
  * 或者是具體的 SIEM 查詢語法 (Splunk/Elastic)。

```

sql
  index=security sourcetype=ffmpeg | search "堆疊溢出" | stats count as num_events

```
* **緩解措施**: 更新 FFmpeg 和 Chrome 到最新版本，配置 WAF 來阻止攻擊。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Heap Overflow (堆溢出)**: 想像一個堆疊被過度填充，導致數據溢出到其他記憶體區域。技術上是指程式嘗試寫入超過堆疊大小的數據，導致堆疊溢出。
* **Stack Overflow (堆疊溢出)**: 想像一個堆疊被過度填充，導致數據溢出到其他記憶體區域。技術上是指程式嘗試寫入超過堆疊大小的數據，導致堆疊溢出。
* **AI 驅動的漏洞掃描**: 使用人工智能技術來自動掃描和發現漏洞。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/06/ai-agent-uncovers-21-zero-days-in.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


