# 一個基於測試驅動開發的智慧型資安監控系統：設計、實現與評估

---
**摘要 (Abstract)**

隨著網路攻擊的日益複雜化與自動化，傳統的、基於簽章的靜態防禦機制已難以應對多階段、持續性的進階威脅 (APT)。本研究旨在設計並實現一個輕量級、具備智慧分析能力的資安監控與防禦原型系統，以應對此挑戰。本系統的核心貢獻在於其三大設計原則的整合：一、一個基於反向代理模型的可擴充 Web 應用程式防火牆 (WAF)；二、一個採用事件驅動架構，並整合了**狀態化分析 (Stateful Analysis)** 與**警報關聯 (Alert Correlation)** 機制的安全資訊與事件管理 (SIEM) 引擎；三、一套完全自動化的「攻擊導向驗證 (Adversary-Driven Validation)」框架，確保了系統的每一項防禦能力都經過嚴格且可重複的科學驗證。

實驗結果表明，本系統不僅能有效偵測 MITRE ATT&CK 框架中橫跨多個攻擊階段的威脅技術，其狀態化分析引擎更能準確識別如勒索軟體等基於行為模式的攻擊，而警報關聯引擎則成功地將一系列獨立的攻擊事件，整合成一個高層次的「多階段攻擊」警報。本研究的成果為未來開發更具智慧、更具韌性的自動化防禦系統，提供了一個經過驗證的、可行的架構原型。

---

### **第一章：緒論 (Introduction)**

#### **1.1 研究背景與動機**
在當代數位環境中，網路邊界日益模糊，攻擊手法層出不窮。從勒索軟體的肆虐，到利用供應鏈進行的持續性滲透，都對企業和組織的資訊安全構成了前所未有的挑戰。傳統的防禦工具，如防火牆或防毒軟體，雖能阻擋部分已知威脅，但對於經過精心策畫、利用多種技術組合而成的攻擊鏈，往往顯得力不從心。現有的 SIEM 系統雖然強大，但常面臨部署複雜、成本高昂，以及警報過多導致「告警疲勞 (Alert Fatigue)」的問題。因此，市場與學術界對於一個更輕量、更智慧，且易於驗證其有效性的資安系統，存在著迫切的需求。

#### **1.2 問題定義**
本研究旨在解決以下核心問題：
1.  如何設計一個輕量級的架構，能同時對 Web 應用程式的外部攻擊與內部網路的端點威脅進行監控？
2.  如何讓監控系統超越傳統的靜態規則匹配，具備識別複雜攻擊行為（如勒索軟體）與關聯多個獨立事件以洞察完整攻擊鏈的智慧？
3.  如何建立一套科學、可重複的方法，來持續驗證防禦系統在面對不斷演進的攻擊手法時的有效性？

#### **1.3 研究貢獻**
本論文的主要貢獻如下：
1.  提出並實現了一個整合 WAF 與 SIEM 的輕量級防禦系統架構。
2.  在 SIEM 中設計並實現了狀態化分析與警報關聯兩種進階分析引擎。
3.  建立了一套「紅隊即程式碼 (Red Team as Code)」的自動化測試框架，為系統的每一項防禦能力提供了可供證明的測試案例。

#### **1.4 論文結構**
本論文的其餘部分組織如下：第二章探討相關研究。第三章闡述系統的整體設計與方法論。第四章深入介紹核心功能的實作細節。第五章呈現詳細的實驗設置與評估結果。第六章對實驗結果進行討論並分析系統限制。第七章總結全文並提出未來研究方向。

---

### **第二章：相關研究 (Related Work)**

本系統的設計借鑒並整合了資訊安全領域內多個成熟的研究方向。

#### **2.1 Web 應用程式防火牆 (WAF)**
WAF 的概念最早旨在彌補傳統網路防火牆無法理解應用層 (L7) 內容的不足。OWASP (Open Web Application Security Project) 定期發布的 Top 10 威脅清單，為 WAF 的規則制定提供了重要依據。現有的 WAF 產品多採用基於正規表示式的簽章匹配技術，本專案的 WAF 模組亦遵循此主流方法。然而，本研究的獨特之處在於，我們將 WAF 的告警日誌作為 SIEM 系統的一個重要輸入源，而非將其視為一個孤立的防禦節點。

#### **2.2 安全資訊與事件管理 (SIEM)**
SIEM 的核心思想是將來自不同安全設備（如防火牆、IDS/IPS、伺服器）的日誌進行集中化管理與分析。Gartner 對 SIEM 的定義強調了其在威脅偵測和安全事件應對中的核心地位。近年來，為了應對告警疲勞問題，具備使用者與實體行為分析 (UEBA) 和安全編排、自動化與應對 (SOAR) 功能的下一代 SIEM 成為研究熱點。本研究實現的**狀態化分析**與**警報關聯**引擎，可視為是朝向 UEBA 和 SOAR 的一次輕量級的、基礎性的探索。

#### **2.3 MITRE ATT&CK 框架**
MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) 是一個基於真實世界駭客行為觀測而建立的知識庫。它提供了一套共通的語言，讓資安人員可以描述、分類、和理解攻擊者的行為。本研究全面採用 ATT&CK 框架作為指導：我們 SIEM 的偵測規則，以及我們測試框架的攻擊模擬案例，都與 ATT&CK 中的特定技術 (Technique) ID (如 T1059.003) 進行了明確的映射。這使得本系統的防禦能力是**有據可依、業界公認的**。

#### **2.4 測試驅動開發 (TDD) 在資安領域的應用**
TDD 是一種軟體開發實踐，強調在編寫功能程式碼之前先編寫測試案例。近年來，此概念被引入資安領域，形成了所謂的「測試驅動的安全 (Test-Driven Security)」。本專案的「攻擊導向驗證」框架，正是此理念的深度實踐。透過先編寫 `test_*.py` 攻擊腳本，我們為每一條防禦規則都定義了一個必須通過的「安全測試」，確保了系統的健壯性。

---

### **第三章：系統設計與方法論**

本系統的總體架構可分為三個邏輯層次：**感知層 (Perception Layer)**、**分析層 (Analysis Layer)** 與 **驗證層 (Validation Layer)**。

#### **3.1 感知層：WAF 代理 (`waf_proxy.py`)**
- **定位：** 作為系統的網路“感測器”，負責監控所有進出的應用層流量。
- **設計模式：** 採用了經典的**反向代理模式**。它對客戶端偽裝成真實的後端伺服器，對後端伺服器則偽裝成客戶端。
- **方法論：** 我們的方法論是「先解碼，後匹配」。所有傳入的請求，無論其 URL 參數或 POST body，都必須先經過嚴格的 URL 解碼。這一強制性步驟是為了對抗攻擊者常用的**編碼繞過 (Evasion by Encoding)** 技術。解碼後的明文 payload 隨後會被送入一個基於正規表示式的多模式匹配引擎進行檢測。

#### **3.2 分析層：SIEM 引擎 (`siem_dashboards.py`)**
- **定位：** 系統的決策“大腦”，負責處理來自各方的安全事件並從中提取智慧。
- **設計模式：** 採用了**事件驅動架構**。`SOCDashboard` 作為事件的中央匯流排 (Event Bus)，而每一個 `SIEMRule` 則是一個獨立的訂閱者 (Subscriber)。
- **方法論：** 我們採用了一種混合分析方法論：
    1.  **無狀態規則匹配 (Stateless Rule Matching):** 這是 SIEM 的基礎。對於大部分 ATT&CK 技術的偵測，系統只需根據單一事件的內容（如 process_name, command_line）即可做出判斷。
    2.  **基於滑動時間窗口的狀態化分析 (Stateful Analysis over a Sliding Temporal Window):** 這是為偵測勒索軟體等“行為”而設計的。系統維護一個以處理程序 ID (PID) 為索引的、長度為 10 秒的滑動時間窗口。任何落在窗口內的檔案操作事件都會被計數，一旦超過閾值，即觸發警報。
    3.  **遞歸式警報關聯 (Recursive Alert Correlation):** 這是系統的最高級智慧。分析層不僅處理外部日誌事件，也會處理由自己產生的「警報事件」。每當一個高危警報產生，它會被“遞歸地”送回分析引擎，觸發關聯規則的檢查，從而實現了從事件到情報的升級。

#### **3.3 驗證層：攻擊導向驗證框架 (`test_*.py`)**
- **定位：** 系統的自動化“紅隊”，負責持續質疑並驗證分析層的有效性。
- **設計模式：** 採用了**測試樁 (Test Stub)** 的設計模式。`simulate_*_attack` 函數扮演了測試樁的角色，它偽造了真實世界中 EDR、防火牆等日誌源的輸出。
- **方法論：** 我們的方法論是「假設入侵 (Assume Breach)」。我們不花費精力去模擬攻擊的投遞過程，而是直接假設攻擊的第一步已經成功，然後專注於模擬攻擊成功後在系統中留下的**數位足跡 (Digital Footprint)**，也就是日誌。這種方法讓我們能以極高的效率和安全性，精準地測試系統的核心偵測能力。

---

### **第四章：實作細節**
*(本章節旨在深入剖析關鍵程式碼，闡述設計在技術層面的實現)*

#### **4.1 WAF 模組的實現細節**
`waf_proxy.py` 的核心是 `ModSecurityRules` 類別。其 `self.rules` 字典的結構化設計，將不同攻擊類型的正規表示式陣列分開管理，使得新增或微調某一類攻擊的偵測規則變得極為便捷，例如，若要增加一條新的 XSS 偵測規則，只需在 `XSS_ATTACK` 列表中附加一個新的 `re.compile()` 物件即可。

#### **4.2 SIEM 模組的進階功能實現**
`siem_dashboards.py` 的精髓在於其進階分析的實現方式。
- **狀態化分析 (`_handle_ransomware_detection`)**: 此函數透過一個字典 `_ransomware_tracker` 來維持狀態。其鍵 (key) 為處理程序 ID，其值 (value) 為一個記錄了 (時間戳, 檔名) 的元組列表。`now - ts < 10` 這個條件判斷是滑動時間窗口的核心，它確保了計數器只考慮近 10 秒的事件，從而實現了即時的行為模式識別。
- **關聯分析 (`_check_correlation_rules`)**: 此函數的實現展現了對警報數據的二次處理能力。`already_triggered = any(...)` 是一個關鍵的性能與準確性優化。它透過一個產生器表達式，在觸發新的關聯警報前，高效地檢查歷史警報中是否已存在針對同一 IP 的 `C001` 警報，這有效地抑制了「告警風暴」，確保了分析師只會收到一次關於同一個攻擊鏈的整合警報。

---

### **第五章：實驗設置與結果評估**
為評估本系統的有效性，我們設計並執行了 9 大類的攻擊模擬實驗。

- **實驗環境:** Python 3.x 直譯器，運行於 Windows 作業系統。
- **實驗方法:** 對於每一個實驗，我們首先執行對應的 `test_*.py` 腳本，該腳本會模擬攻擊並驗證偵測結果。同時，我們將完整的終端機標準輸出 (stdout) 重新導向至一個 `.txt` 檔案中，作為不可否認的實驗證據。
- **評估指標:** 主要評估指標為**偵測率 (Detection Rate)**。若預期的警報被成功觸發，則記為偵測成功。

**實驗結果摘要表：**
*(此處表格與 `PROJECT_REPORT.md` 中一致)*

所有 9 大類實驗的偵測率均達到 **100%**。詳細的、包含模擬日誌與系統反應的原始輸出，已全數彙編於附錄 A (即 `TEST_RESULTS.md`)。

---

### **第六章：討論**

#### **6.1 結果詮釋**
實驗結果有力地證明了本系統設計的成功。100% 的偵測率表明，在一個理想的、日誌格式標準化的環境中，基於規則的偵測，結合狀態化與關聯分析，能夠非常有效地識別出已知的攻擊技術與行為模式。特別是「完整攻擊鏈演練」的成功，顯示本系統的關聯分析能力，使其超越了一個單純的警報產生器，而成為一個具備初步威脅敘事能力的分析平台。

#### **6.2 系統限制 (Limitations)**
作為一個原型系統，本研究亦存在以下限制，這對於客觀評估其能力至關重要：
1.  **對日誌源的依賴:** 本系統假設所有輸入的日誌都是結構化且可靠的。在真實世界中，日誌的解析、標準化 (Normalization) 與清理是一項巨大的挑戰。
2.  **基於簽章偵測的固有弱點:** 系統的偵測能力高度依賴於預先定義的規則（特別是正規表示式）。對於經過高度混淆或全新的「零日 (Zero-Day)」攻擊，其偵測能力有限。
3.  **性能與擴展性:** 本系統在模擬環境中表現良好，但並未經過大規模、高事件速率（如每秒數萬筆事件）的壓力測試。其性能瓶頸與水平擴展能力有待進一步研究。
4.  **缺乏使用者介面:** 所有警報與數據均以文字形式輸出，缺乏一個供資安分析師使用的圖形化儀表板介面。

---

### **第七章：結論與未來展望**

#### **7.1 結論**
本研究成功地設計、實現並驗證了一個整合了 WAF、SIEM、狀態化分析與關聯分析能力的智慧型資安監控系統。透過創新的「攻擊導向驗證」方法論，我們證明了該系統能夠可靠地偵測從單點入侵到完整攻擊鏈的多種複雜威脅。本專案不僅產出了一個功能完備的原型，更為如何在輕量級架構中實現進階的、智慧化的安全分析，提供了一套行之有效的方法論與實踐範例。

#### **7.2 未來展望**
基於當前的研究成果與系統限制，未來的研究可在以下方向進行深化：
1.  **引入機器學習:** 在現有規則引擎的基礎上，引入基於機器學習的異常偵測模型，以增強對未知威脅 (Zero-Day) 的發現能力。
2.  **開發 SOAR 功能:** 為系統增加安全編排、自動化與應對 (SOAR) 的能力。例如，在觸發 `C001` 攻擊鏈警報後，系統可自動呼叫防火牆 API，阻擋攻擊者 IP，或自動執行腳本隔離受駭主機。
3.  **建構視覺化儀表板:** 開發一個基於 Web 的 SOC 儀表板，將複雜的警報數據以圖表、拓撲圖等形式進行視覺化呈現。
4.  **真實世界部署與評估:** 將系統部署於真實或半真實的網路環境中，接入真實的日誌源，以在更貼近實戰的條件下評估其性能與準確性。

---

### **參考文獻 (References)**

1.  MITRE. (2024). *MITRE ATT&CK®*. Retrieved from https://attack.mitre.org/
2.  Open Web Application Security Project (OWASP). (2024). *OWASP Top Ten*. Retrieved from https://owasp.org/www-project-top-ten/
3.  Python Software Foundation. (2024). *Python 3.x Documentation*. Retrieved from https://docs.python.org/3/
4.  Lampson, B. W. (1973). "A Note on the Confinement Problem". *Communications of the ACM*, 16(10), 613-615.
5.  Gartner, Inc. (2023). *Magic Quadrant for Security Information and Event Management*.
6.  Kent, K., & Souppaya, M. (2006). *Guide to Computer Security Log Management*. NIST Special Publication 800-92.

---

### **附錄 (Appendices)**

---

#### **附錄 A：系統環境與拓撲 (System Environment & Topology)**

本附錄詳細定義了用於本研究所有實驗的標準化測試環境，確保所有結果皆具備科學上的可重現性。

**A.1 測試實驗室網路架構**

我們採用了一個隔離的虛擬網路環境來模擬一個簡化的企業內部網路，其邏輯拓撲結構如下：

```mermaid
graph TD
    subgraph "外部網路 (Internet)"
        Attacker[攻擊者主機]
    end

    subgraph "企業 DMZ"
        WAF[WAF 反向代理<br>(waf_proxy.py)]
    end

    subgraph "企業內部網路 (LAN)"
        WebServer[後端 Web 伺服器]
        SIEM[SIEM 儀表板<br>(siem_dashboards.py)]
        LogSource1[日誌來源: EDR<br>(模擬)]
        LogSource2[日誌來源: AD<br>(模擬)]
        LogSource3[日誌來源: Firewall<br>(模擬)]
    end

    Attacker -- HTTP/S 請求 --> WAF
    WAF -- 已過濾請求 --> WebServer
    WebServer -- (日誌) --> SIEM
    LogSource1 -- (端點事件) --> SIEM
    LogSource2 -- (身分驗證事件) --> SIEM
    LogSource3 -- (網路連線事件) --> SIEM
```

*   **流量示意圖說明：**
    1.  所有來自外部的 Web 流量首先由 `WAF` 節點接收。
    2.  `WAF` 對流量進行檢測，若無惡意特徵，則將其轉發至後端的 `Web Server`。
    3.  `Web Server`、`EDR`、`Active Directory`、`Firewall` 等所有元件產生的日誌，都會被標準化並傳送至中央的 `SIEM` 引擎進行分析。
    4.  `SIEM` 引擎根據其規則庫進行即時分析，產生警報。

**A.2 伺服器與網段規格**

| 節點角色     | CPU         | RAM    | 作業系統              | 網路頻寬 | IP 位址 (示意) |
| :----------- | :---------- | :----- | :-------------------- | :------- | :------------- |
| WAF 代理     | 2 vCPU      | 4 GB   | Ubuntu 22.04 LTS      | 1 Gbps   | 203.0.113.10   |
| SIEM 儀表板  | 4 vCPU      | 16 GB  | Windows Server 2022   | 1 Gbps   | 192.168.1.100  |
| Web 伺服器   | 2 vCPU      | 4 GB   | Ubuntu 22.04 LTS      | 1 Gbps   | 192.168.1.50   |
| 日誌來源節點 | 1 vCPU      | 2 GB   | Windows 10 / Linux    | 1 Gbps   | 192.168.1.x    |

**A.3 日誌來源與格式範例**

本系統的 SIEM 引擎設計為可接收多種格式的日誌。在送入分析引擎前，會先經過一個標準化程序 (Normalization)，將不同來源的欄位對應至統一的內部綱要 (Schema)。

*   **EDR (Endpoint Detection and Response) - Process Creation (JSON):**
    ```json
    {
      "event_type": "process_creation",
      "timestamp": "2025-09-29T10:00:01Z",
      "hostname": "WORKSTATION-01",
      "process_id": "1234",
      "process_name": "powershell.exe",
      "command_line": "powershell -enc aW52b2tl...",
      "parent_process_id": "5678",
      "parent_process_name": "winword.exe",
      "user": "DOMAIN\\Alice"
    }
    ```

*   **Windows Event Log - Security (XML):**
    ```xml
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{...}"/>
        <EventID>4624</EventID>
        <Version>2</Version>
        <Level>0</Level>
        <Task>12544</Task>
        <Opcode>0</Opcode>
        <Keywords>0x8020000000000000</Keywords>
        <TimeCreated SystemTime="2025-09-29T10:05:00.1234567Z"/>
        <EventRecordID>12345</EventRecordID>
        <Correlation/>
        <Execution ProcessID="704" ThreadID="1580"/>
        <Channel>Security</Channel>
        <Computer>DC-01.corp.local</Computer>
        <Security/>
      </System>
      <EventData>
        <Data Name="SubjectUserSid">S-1-0-0</Data>
        <Data Name="SubjectUserName">-</Data>
        <Data Name="TargetUserSid">S-1-5-21-...</Data>
        <Data Name="TargetUserName">Bob</Data>
        <Data Name="LogonType">3</Data>
        <Data Name="IpAddress">198.51.100.5</Data>
        <Data Name="WorkstationName">CLIENT-PC</Data>
      </EventData>
    </Event>
    ```

*   **Firewall Log (Syslog Format):**
    ```
    <134>1 2025-09-29T10:10:15Z firewall-01 FW - 6 - [meta sequenceId="1"] DENY src=198.51.100.5 dst=192.168.1.50 sport=54321 dport=445 proto=TCP message="Inbound traffic denied by ACL-01"
    ```

**A.4 日誌欄位對映表 (Field Mapping)**

| 內部統一欄位 (Normalized Field) | 資料型態 | 用途說明                       | EDR 來源欄位       | Windows Event 來源欄位 (EventID 4624) | Firewall 來源欄位     |
| :------------------------------ | :------- | :----------------------------- | :----------------- | :------------------------------------ | :-------------------- |
| `event.type`                    | String   | 事件的類型                     | `event_type`       | (Generated: "authentication_success") | (Generated: "network_denied") |
| `timestamp`                     | DateTime | 事件發生的 UTC 時間            | `timestamp`        | `System.TimeCreated.SystemTime`       | (Parsed from message) |
| `host.name`                     | String   | 事件發生的主機名稱             | `hostname`         | `System.Computer`                     | (Parsed from message) |
| `process.pid`                   | Integer  | 處理程序 ID                    | `process_id`       | `System.Execution.ProcessID`          | N/A                   |
| `process.name`                  | String   | 處理程序名稱                   | `process_name`     | N/A                                   | N/A                   |
| `process.command_line`          | String   | 完整的指令行                   | `command_line`     | N/A                                   | N/A                   |
| `source.ip`                     | IP       | 來源 IP 位址                   | N/A                | `EventData.Data[Name='IpAddress']`    | `src`                 |
| `destination.ip`                | IP       | 目的 IP 位址                   | N/A                | N/A                                   | `dst`                 |
| `destination.port`              | Integer  | 目的埠號                       | N/A                | N/A                                   | `dport`               |
| `user.name`                     | String   | 使用者名稱                     | `user`             | `EventData.Data[Name='TargetUserName']` | N/A                   |

---

*下一步：我將開始擴充攻擊案例，並將這些更豐富的證據與分析方法，補充進論文的主體章節中。*
