---
layout: post
title:  "Webworm Deploys EchoCreep and GraphWorm Backdoors Using Discord and MS Graph API"
date:   2026-05-20 14:44:35 +0000
categories: [security]
severity: high
---

# 🔥 解析 Webworm 威脅群體的 Discord 和 Microsoft Graph API 命令與控制技術

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Discord API`, `Microsoft Graph API`, `Custom Backdoors`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Webworm 威脅群體利用 Discord 和 Microsoft Graph API 建立命令與控制（C2）通道，實現遠程代碼執行和資料傳輸。
* **攻擊流程圖解**:
  1. Webworm 威脅群體創建自訂後門（Backdoor），例如 EchoCreep 和 GraphWorm。
  2. 後門使用 Discord API 或 Microsoft Graph API 與 C2 伺服器進行通信。
  3. C2 伺服器發送命令和資料給後門，後門執行命令並傳回結果。
* **受影響元件**: Discord API、Microsoft Graph API、Windows 作業系統

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有 Discord 或 Microsoft Graph API 的使用權限和網路存取權。
* **Payload 建構邏輯**:

    ```
    
    python
    import requests
    
    # Discord API
    discord_api_url = "https://discord.com/api/v9"
    discord_token = "YOUR_DISCORD_TOKEN"
    
    # Microsoft Graph API
    graph_api_url = "https://graph.microsoft.com/v1.0"
    graph_token = "YOUR_GRAPH_TOKEN"
    
    # 建構 Payload
    payload = {
        "content": "YOUR_COMMAND"
    }
    
    # 發送 Payload
    response = requests.post(discord_api_url + "/channels/CHANNEL_ID/messages", headers={"Authorization": "Bearer " + discord_token}, json=payload)
    
    ```
  *範例指令*: 使用 `curl` 發送 Payload

```

bash
curl -X POST \
  https://discord.com/api/v9/channels/CHANNEL_ID/messages \
  -H 'Authorization: Bearer YOUR_DISCORD_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"content": "YOUR_COMMAND"}'

```
* **繞過技術**: 可以使用代理伺服器或 VPN 來繞過防火牆和入侵偵測系統。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| Hash | `YOUR_HASH_VALUE` |
| IP | `YOUR_IP_ADDRESS` |
| Domain | `YOUR_DOMAIN_NAME` |
| File Path | `YOUR_FILE_PATH` |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule Discord_API_C2 {
      meta:
        description = "Discord API C2 通信"
        author = "YOUR_NAME"
      strings:
        $discord_api_url = "https://discord.com/api/v9"
      condition:
        $discord_api_url in (http.request.uri)
    }
    
    ```
  或者是使用 Snort/Suricata Signature

```

snort
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Discord API C2 通信"; content:"https://discord.com/api/v9"; sid:1000001; rev:1;)

```
* **緩解措施**: 可以設定 Discord 和 Microsoft Graph API 的使用權限和存取控制，限制不必要的 API 存取和資料傳輸。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Discord API**: Discord 的應用程式介面（API），允許開發人員存取 Discord 的功能和資料。
* **Microsoft Graph API**: Microsoft 的應用程式介面（API），允許開發人員存取 Microsoft 的功能和資料。
* **Custom Backdoor**: 自訂後門，是一種惡意程式，允許攻擊者遠程控制和存取受害者的系統。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://thehackernews.com/2026/05/webworm-deploys-echocreep-and-graphworm.html)
- [MITRE ATT&CK](https://attack.mitre.org/)


