---
layout: post
title:  "Google Disrupts UNC2814 GRIDTIDE Campaign After 53 Breaches Across 42 Countries"
date:   2026-02-25 18:56:24 +0000
categories: [security]
severity: critical
---

# 🚨 解析 UNC2814 網絡攻擊：GRIDTIDE 後門與 Google Sheets API 的利用
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `API Abuse`, `Living-off-the-Land (LotL)`, `SoftEther VPN`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: UNC2814 攻擊者利用 Google Sheets API 作為 C2 通道，透過 API 呼叫來隱藏惡意流量。
* **攻擊流程圖解**:
  1. 攻擊者創建 Google Sheets 文件並設定 API 權限。
  2. 攻擊者將 GRIDTIDE 後門上傳到受害者端點。
  3. GRIDTIDE 後門透過 Google Sheets API 向攻擊者發送命令並接收回應。
* **受影響元件**: Google Sheets API、GRIDTIDE 後門、SoftEther VPN

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 Google Sheets API 權限和受害者端點的存取權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # 定義 Google Sheets API endpoint
    endpoint = "https://sheets.googleapis.com/v4/spreadsheets/{spreadsheetId}/values/{range}"
    
    # 定義 API 權限和 spreadsheetId
    api_key = "YOUR_API_KEY"
    spreadsheetId = "YOUR_SPREADSHEET_ID"
    
    # 定義範圍和值
    range_ = "A1:B2"
    values = [["命令", "回應"]]
    
    # 發送 API 呼叫
    response = requests.post(endpoint, headers={"Authorization": f"Bearer {api_key}"}, json={"values": values})
    
    # 處理回應
    if response.status_code == 200:
        print("命令發送成功")
    else:
        print("命令發送失敗")
    
    ```
* **繞過技術**: 攻擊者可以使用 SoftEther VPN 來建立加密連接，繞過防火牆和入侵檢測系統。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| `GRIDTIDE 後門` | `攻擊者 IP` | `googleapis.com` | `/etc/systemd/system/xapt.service` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule GRIDTIDE_Detection {
        meta:
            description = "GRIDTIDE 後門偵測"
            author = "Your Name"
        strings:
            $a = "GRIDTIDE" ascii
            $b = "Google Sheets API" ascii
        condition:
            $a and $b
    }
    
    ```
* **緩解措施**: 更新 Google Sheets API 權限，禁用不必要的 API 權限，使用防火牆和入侵檢測系統來檢測和阻止惡意流量。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **API Abuse**: 想像 API 是一扇門，攻擊者可以透過這扇門來存取敏感資料或執行命令。技術上是指攻擊者利用 API 的漏洞或弱點來進行惡意活動。
* **Living-off-the-Land (LotL)**: 想像攻擊者是個遊客，需要利用現有的資源來生存。技術上是指攻擊者利用現有的系統工具和功能來進行惡意活動，而不是使用惡意軟體。
* **SoftEther VPN**: 想像 SoftEther VPN 是一條秘密通道，攻擊者可以透過這條通道來建立加密連接。技術上是指 SoftEther VPN 是一種 VPN 軟體，可以用來建立加密連接和隱藏惡意流量。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/02/google-disrupts-unc2814-gridtide.html)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


