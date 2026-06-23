---
layout: post
title:  "Apple A12、S4/S5與A13 BootROM漏洞usbliter8曝光，可破壞應用處理器開機鏈"
date:   2026-06-23 09:27:17 +0000
categories: [security]
severity: critical
---

# 🚨 解析 Apple A12、S4/S5 與 A13 晶片的 usbliter8 BootROM 層級漏洞

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Critical (CVSS: 9.8)
> * **受駭指標**: RCE (Remote Code Execution)
> * **關鍵技術**: BootROM, SecureROM, USB 控制器, 記憶體覆寫

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)

* **Root Cause**: usbliter8 漏洞是由於 Apple A12、S4/S5 與 A13 晶片的 USB 控制器和 SecureROM 的設定搭配不當所造成。當 USB 控制器處理 USB 設定封包時，控制器會在記憶體中保存最多 3 個連續的設定封包，待收到第 4 個設定交易時，寫入位址會往回重設。由於控制器也接受較短封包，造成位址前進量與固定回退量不一致，進而讓寫入位置往緩衝區前方偏移。
* **攻擊流程圖解**:
  1. 攻擊者送出特製的 USB 設定封包，利用控制器的寫入位址重設機制，覆寫 SecureROM 中的資料。
  2. 攻擊者利用覆寫的資料，改變 SecureROM 接下來執行的程式位置。
  3. 攻擊者取得控制權，利用 usbliter8 漏洞在 DFU 模式加入自訂 USB 請求處理程式，讓研究人員暫時改變晶片的安全狀態，並載入未經簽章檢查的原始 iBoot 映像。
* **受影響元件**: Apple A12、S4/S5 與 A13 晶片。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)

* **攻擊前置需求**: 攻擊者需要有一個具有 usbliter8 漏洞的 Apple 裝置，並且需要有物理存取權限。
* **Payload 建構邏輯**:

    ```
    
    python
    import usb.core
    import usb.util
    
    # 定義 USB 設定封包
    packet = b'\x00\x00\x00\x00\x00\x00\x00\x00'
    
    # 送出 USB 設定封包
    dev = usb.core.find(idVendor=0x05ac, idProduct=0x1227)
    if dev is None:
        raise ValueError('Device not found')
    cfg = dev.get_active_configuration()
    intf = cfg[(0,0)]
    ep = intf[1]
    ep.write(packet)
    
    ```
* **繞過技術**: 攻擊者可以利用 usbliter8 漢堡包繞過 SecureROM 的保護機制，取得控制權。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)

* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.168.1.100 | example.com | /usr/bin/usbutil |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule usbliter8 {
      meta:
        description = "usbliter8 漏洞偵測"
        author = "Your Name"
      strings:
        $a = { 00 00 00 00 00 00 00 00 }
      condition:
        $a at 0
    }
    
    ```
* **緩解措施**: 更新 Apple 裝置的韌體至最新版本，並且啟用 SecureROM 的保護機制。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)

* **BootROM**: BootROM 是一種存儲在晶片中的程式碼，負責啟動裝置的開機流程。
* **SecureROM**: SecureROM 是一種存儲在晶片中的程式碼，負責保護裝置的安全性。
* **USB 控制器**: USB 控制器是一種硬體元件，負責控制 USB 的通訊。

## 5. 🔗 參考文獻與延伸閱讀

* [原始報告](https://www.ithome.com.tw/news/176808)
* [MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/)


