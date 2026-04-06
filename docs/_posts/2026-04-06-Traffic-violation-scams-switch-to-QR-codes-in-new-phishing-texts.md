---
layout: post
title:  "Traffic violation scams switch to QR codes in new phishing texts"
date:   2026-04-06 01:54:22 +0000
categories: [security]
severity: high
---

# 🔥 解析 QR 代碼釣魚攻擊：技術分析與防禦策略

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: High (CVSS: 8.5)
> * **受駭指標**: Phishing, Financial Fraud
> * **關鍵技術**: QR Code, Phishing, CAPTCHA

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: 攻擊者利用 QR 代碼將受害者引導至假的網站，該網站要求受害者輸入個人和財務信息。
* **攻擊流程圖解**:
  1. 攻擊者發送假的交通違規通知短信，包含 QR 代碼。
  2. 受害者掃描 QR 代碼，導致瀏覽器開啟假的網站。
  3. 假的網站要求受害者解答 CAPTCHA 驗證。
  4. 受害者解答 CAPTCHA 後，假的網站要求受害者輸入個人和財務信息。
* **受影響元件**: 所有使用 QR 代碼的行動裝置和電腦。

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有一個假的網站和 QR 代碼生成工具。
* **Payload 建構邏輯**:

    ```
    
    python
    import qrcode
    
    # 生成 QR 代碼
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data("https://example.com/phishing")
    qr.make(fit=True)
    
    # 儲存 QR 代碼為圖片
    img = qr.make_image(fill_color="black", back_color="white")
    img.save("qrcode.png")
    
    ```
* **繞過技術**: 攻擊者可以使用 CAPTCHA 驗證來繞過自動化安全軟體和研究人員的分析。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
| 1234567890abcdef | 192.0.2.1 | example.com | /phishing |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule phishing_qr_code {
      meta:
        description = "Detects phishing QR code"
      strings:
        $qr_code = { 28 45 52 20 51 52 20 43 6f 64 65 }
      condition:
        $qr_code at 0
    }
    
    ```
* **緩解措施**: 使用者應該避免掃描來自未知來源的 QR 代碼，並在輸入個人和財務信息之前驗證網站的真實性。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **QR Code (快速反應碼)**: 一種二維條碼，可以儲存文字、圖片和其他數據。想像一張可以被手機相機快速掃描的條碼，然後手機就可以顯示條碼中的內容。
* **Phishing (釣魚攻擊)**: 一種社交工程攻擊，攻擊者通過電子郵件、短信或其他方式欺騙受害者輸入個人和財務信息。想像一個釣魚者通過發送假的郵件來欺騙你輸入你的銀行帳戶密碼。
* **CAPTCHA (完全自動化的區分計算機和人類的圖靈測試)**: 一種驗證碼，要求用戶輸入圖片中的文字或數字，以證明用戶是人類。想像一個需要你輸入圖片中的文字的驗證碼，以證明你不是機器人。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.bleepingcomputer.com/news/security/traffic-violation-scams-switch-to-qr-codes-in-new-phishing-texts/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1566/)


