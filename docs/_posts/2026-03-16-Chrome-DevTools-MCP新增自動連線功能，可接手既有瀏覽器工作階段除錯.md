---
layout: post
title:  "Chrome DevTools MCP新增自動連線功能，可接手既有瀏覽器工作階段除錯"
date:   2026-03-16 18:54:25 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Chrome DevTools MCP Server 自動連線功能的安全性
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: Info Leak
> * **關鍵技術**: `Chrome DevTools`, `MCP Server`, `遠端除錯`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: Chrome DevTools MCP Server 的自動連線功能允許開發者直接連接到使用中的 Chrome 瀏覽器工作階段，續用既有登入狀態，並接手 DevTools 中已開啟的除錯脈絡。這個功能建立在 Chrome M144 新增的遠端除錯機制上，Chrome 預設不開放這類連線，必須由開發者先手動啟用。
* **攻擊流程圖解**: 
  1. 開發者啟用 Chrome DevTools MCP Server 的自動連線功能。
  2. MCP Server 向執行中的 Chrome 請求建立遠端除錯工作階段。
  3. 使用者決定是否允許連線。
  4. 連線啟用後，Chrome 上方顯示目前瀏覽器正由自動化測試軟體控制的提示。
* **受影響元件**: Chrome M144 及以上版本。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 需要有 Chrome DevTools MCP Server 的存取權限。
* **Payload 建構邏輯**: 
    * 可以使用以下 Python 代碼建立一個簡單的 MCP Server 連線：

```

python
import socket

# MCP Server 連線設定
mcp_server = 'localhost'
mcp_port = 9222

# 建立連線
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((mcp_server, mcp_port))

# 送出請求
request = 'GET /devtools/page/1 HTTP/1.1\r\nHost: {}\r\n\r\n'.format(mcp_server)
sock.sendall(request.encode())

# 接收回應
response = sock.recv(1024)
print(response.decode())

```
    * 可以使用 `curl` 指令測試 MCP Server 連線：

```

bash
curl -X GET 'http://localhost:9222/devtools/page/1'

```
* **繞過技術**: 可以使用代理伺服器或 VPN 來繞過網路限制。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| 類型 | 值 |
| --- | --- |
| IP | 127.0.0.1 |
| Port | 9222 |
| File Path | /devtools/page/1 |* **偵測規則 (Detection Rules)**:
  * 可以使用以下 YARA Rule 來偵測 MCP Server 連線：

```

yara
rule MCP_Server_Connect {
  meta:
    description = "MCP Server 連線偵測"
  strings:
    $mcp_server = "GET /devtools/page/1 HTTP/1.1"
  condition:
    $mcp_server
}

```
  * 可以使用以下 Snort Signature 來偵測 MCP Server 連線：

```

snort
alert tcp any any -> any 9222 (msg:"MCP Server 連線偵測"; content:"GET /devtools/page/1 HTTP/1.1"; sid:1000001;)

```
* **緩解措施**: 可以關閉 Chrome DevTools MCP Server 的自動連線功能，或者設定 MCP Server 只允許特定 IP 地址存取。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **MCP Server (Multi-Client Proxy Server)**: 一種允許多個客戶端連接到單一伺服器的代理伺服器。
* **遠端除錯 (Remote Debugging)**: 一種允許開發者在遠端機器上除錯程式的技術。
* **Chrome DevTools**: 一種允許開發者除錯和測試網頁應用程式的工具。

## 5. 🔗 參考文獻與延伸閱讀
- [Chrome DevTools 官方文件](https://developer.chrome.com/docs/devtools/)
- [MCP Server 官方文件](https://developer.chrome.com/docs/devtools/mcp-server/)
- [遠端除錯技術文獻](https://en.wikipedia.org/wiki/Remote_debugging)


