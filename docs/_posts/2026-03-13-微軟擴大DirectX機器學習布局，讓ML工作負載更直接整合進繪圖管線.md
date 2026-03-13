---
layout: post
title:  "微軟擴大DirectX機器學習布局，讓ML工作負載更直接整合進繪圖管線"
date:   2026-03-13 12:42:26 +0000
categories: [security]
severity: medium
---

# ⚠️ 解析 DirectX 新一波機器學習相關技術布局

> **⚡ 戰情快篩 (TL;DR)**
> * **嚴重等級**: Medium (CVSS 分數：6.5)
> * **受駭指標**: 信息洩露 (Info Leak)
> * **關鍵技術**: `DX Linear Algebra`, `DirectX Compute Graph Compiler`, `HLSL`

## 1. 🔬 漏洞原理與技術細節 (Deep Dive)
* **Root Cause**: DirectX 新的機器學習相關技術布局，包括 DX Linear Algebra 和 DirectX Compute Graph Compiler，旨在讓 Windows 遊戲在 DirectX 繪圖工作管線內更直接地執行機器學習工作負載。
* **攻擊流程圖解**: 
    1. 攻擊者利用 DX Linear Algebra 和 DirectX Compute Graph Compiler 的功能，嘗試在 DirectX 繪圖工作管線內執行機器學習工作負載。
    2. 攻擊者可能會利用 HLSL 的硬體加速的向量乘矩陣運算，嘗試進行降噪、時間性升尺度等工作負載。
* **受影響元件**: DirectX 12、HLSL、DX Linear Algebra、DirectX Compute Graph Compiler

## 2. ⚔️ 紅隊實戰：攻擊向量與 Payload (Red Team Operations)
* **攻擊前置需求**: 攻擊者需要有 DirectX 12 和 HLSL 的知識和經驗。
* **Payload 建構邏輯**:

    ```
    
    c
    // 範例 Payload 結構
    struct Payload {
        float* data;
        int length;
    };
    
    // 範例指令
    void attack() {
        // 創建 Payload
        Payload payload;
        payload.data = (float*)malloc(1024 * sizeof(float));
        payload.length = 1024;
    
        // 利用 DX Linear Algebra 和 DirectX Compute Graph Compiler 執行機器學習工作負載
        // ...
    }
    
    ```
    * **範例指令**: `curl` 或 `nmap` 可以用於掃描目標系統的 DirectX 12 和 HLSL 支持。
* **繞過技術**: 攻擊者可能會利用 WAF 或 EDR 繞過技巧，例如使用加密或隱碼技術來隱藏 Payload。

## 3. 🛡️ 藍隊防禦：偵測與緩解 (Blue Team Defense)
* **IOCs (入侵指標)**:

| Hash | IP | Domain | File Path |
| --- | --- | --- | --- |
|  |  |  |  |* **偵測規則 (Detection Rules)**:

    ```
    
    yara
    rule DirectX_ML_Attack {
        meta:
            description = "DirectX 機器學習攻擊"
            author = "Your Name"
        strings:
            $dx_linear_algebra = "DXLinearAlgebra"
            $directx_compute_graph_compiler = "DirectXComputeGraphCompiler"
        condition:
            $dx_linear_algebra and $directx_compute_graph_compiler
    }
    
    ```
    * **SIEM 查詢語法** (Splunk/Elastic): `index=directx_ml_attack sourcetype=directx_ml_attack`
* **緩解措施**: 除了更新修補之外，還可以修改 DirectX 12 和 HLSL 的設定，例如禁用 DX Linear Algebra 和 DirectX Compute Graph Compiler。

## 4. 📚 專有名詞與技術概念解析 (Technical Glossary)
* **DX Linear Algebra**: 一種用於著色器層級運算的線性代數庫，提供硬體加速的向量乘矩陣運算。
* **DirectX Compute Graph Compiler**: 一種新的 DirectX ML 編譯器 API，用於讓來自現代框架的模型圖先依裝置條件完成圖分析、記憶體規畫與運算子融合，再轉成可直接整合進 D3D12 佇列與命令串列的工作負載。
* **HLSL**: 高級著色器語言 (High-Level Shading Language)，是一種用於著色器編程的語言。

## 5. 🔗 參考文獻與延伸閱讀
- [原始報告](https://www.ithome.com.tw/news/174393)
- [MITRE ATT&CK](https://attack.mitre.org/)


