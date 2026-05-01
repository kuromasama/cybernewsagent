---
layout: post
title:  "Microsoft fixes Remote Desktop warnings displaying incorrectly"
date:   2026-05-01 13:04:50 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 Windows 遠端桌面安全警告顯示錯誤漏洞
> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS: 6.5)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: `Remote Desktop Protocol`, `Windows Security Warnings`, `Display Scaling`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 漏洞是由於 Windows 遠端桌面連線安全警告對話框在多顯示器環境下，當顯示器的縮放設定不同時，對話框的渲染會出現錯誤，導致按鈕和文字的顯示位置不正確。
* **攻擊流程圖解**: 
  1. 使用者嘗試連線到遠端桌面。
  2. Windows 顯示安全警告對話框。
  3. 對話框的渲染出現錯誤，按鈕和文字的顯示位置不正確。
* **受影響元件**: Windows 11 (KB5083768 & KB5083769), Windows 10 (KB5082200), Windows Server (KB5082063)

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有遠端桌面連線的權限和網路位置。
* **Payload 建構邏輯**:

    ```
    
    python
    import os
    
    # 建構遠端桌面連線檔案
    def build_rdp_file():
        rdp_file = "full address:s:192.168.1.100\n"
        rdp_file += "username:s:admin\n"
        rdp_file += "password:s:password123\n"
        return rdp_file
    
    # 儲存遠端桌面連線檔案
    def save_rdp_file(rdp_file):
        with open("example.rdp", "w") as f:
            f.write(rdp_file)
    
    # 執行遠端桌面連線
    def execute_rdp_file():
        os.system("mstsc example.rdp")
    
    # 主程式
    if __name__ == "__main__":
        rdp_file = build_rdp_file()
        save_rdp_file(rdp_file)
        execute_rdp_file()
    
    ```
    *範例指令*: 使用 `curl` 下載遠端桌面連線檔案，然後使用 `mstsc` 執行連線。
* **繞過技術**: 攻擊者可以使用社交工程術來欺騙使用者下載和執行惡意的遠端桌面連線檔案。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | C:\example.rdp |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule RemoteDesktopExploit {
        meta:
            description = "遠端桌面連線檔案惡意程式碼"
            author = "Your Name"
        strings:
            $a = "full address:s:"
            $b = "username:s:"
            $c = "password:s:"
        condition:
            all of them
    }
    
    ```
    或者是具體的 **SIEM 查詢語法** (Splunk/Elastic):

    ```
    
    sql
    index=security sourcetype=rdp_connection 
    
    | stats count as num_connections by src_ip, dest_ip
    | where num_connections > 10
    ```
* **緩解措施**: 除了更新修補之外，還可以設定遠端桌面連線的安全性設定，例如啟用多因素驗證和限制遠端桌面連線的權限。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **Remote Desktop Protocol (RDP)**: 一種遠端桌面連線協定，允許使用者連線到遠端的 Windows 電腦。
* **Windows Security Warnings**: Windows 的安全警告系統，會顯示安全警告對話框來提醒使用者注意安全問題。
* **Display Scaling**: 顯示器的縮放設定，會影響遠端桌面連線的顯示效果。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/microsoft/microsoft-fixes-remote-desktop-warnings-displaying-incorrectly/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1210/)


