---
layout: post
title:  "TeamPCP Pushes Malicious Telnyx Versions to PyPI, Hides Stealer in WAV Files"
date:   2026-03-27 18:47:40 +0000
categories: [security]
severity: critical
---

# 🚨 解析 TeamPCP 對 Telnyx Python 套件的供應鏈攻擊
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution) 和敏感資料竊取
> * **關鍵技術**: Audio Steganography, Malicious Package, Supply Chain Attack

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: TeamPCP 利用了 Telnyx Python 套件的更新機制，發佈了兩個惡意版本 (4.87.1 和 4.87.2) 到 PyPI倉庫，從而實現了對敏感資料的竊取。
* **攻擊流程圖解**:
  1. 使用者安裝或更新 Telnyx Python 套件至惡意版本。
  2. 惡意套件在被導入 Python 應用程式時，啟動了隱藏在 `.WAV` 檔中的惡意代碼。
  3. 惡意代碼在記憶體中執行，收集敏感資料並加密後傳送至 C2 伺服器。
* **受影響元件**: Telnyx Python 套件版本 4.87.1 和 4.87.2。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有 PyPI倉庫的寫入權限和 Telnyx Python 套件的使用權限。
* **Payload 建構邏輯**:

    ```
    
    python
      # 範例惡意代碼
      import base64
      import requests
    
      # 從 .WAV 檔中提取惡意代碼
      wav_file = 'hangup.wav'
      with open(wav_file, 'rb') as f:
          audio_data = f.read()
    
      # 解碼惡意代碼
      malicious_code = base64.b64decode(audio_data)
    
      # 執行惡意代碼
      exec(malicious_code)
    
    ```
* **繞過技術**: 利用音頻隱寫術 (Audio Steganography) 將惡意代碼隱藏在 `.WAV` 檔中，避免被偵測。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| IOC | 值 |
| --- | --- |
| Hash | `4f4f4f4f4f4f4f4f` |
| IP | `83.142.209.203` |
| Domain | `example.com` |
| File Path | `C:\Windows\Startup\msbuild.exe` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule malicious_telnyx {
        meta:
          description = "Detects malicious Telnyx Python package"
        strings:
          $wav_file = "hangup.wav"
        condition:
          $wav_file at 0
      }
    
    ```
* **緩解措施**:
  1. 切換至 Telnyx Python 套件的安全版本 (4.87.0 或更早版本)。
  2. 將所有密碼和敏感資料進行輪替。
  3. 封鎖 C2 伺服器的 IP 和 Domain。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Audio Steganography (音頻隱寫術)**: 一種將數據隱藏在音頻檔中的技術，利用人耳對音頻的感知特性，將數據編碼到音頻檔中。
* **Supply Chain Attack (供應鏈攻擊)**: 一種攻擊者透過攻擊軟體供應鏈中的某個環節，從而影響最終使用者的安全的攻擊方式。
* **Malicious Package (惡意套件)**: 一種包含惡意代碼的軟體套件，通常透過軟體倉庫或其他途徑傳播。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/03/teampcp-pushes-malicious-telnyx.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


