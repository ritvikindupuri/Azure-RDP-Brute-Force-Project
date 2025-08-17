# Azure-Native RDP Brute Force Detection Pipeline

## 📌 Overview
This project demonstrates the design and implementation of a cloud-native security pipeline for detecting and investigating brute force attacks targeting a Windows Virtual Machine (VM) in Microsoft Azure. It showcases the full lifecycle of threat detection and incident response using Microsoft Sentinel.

## 🧱 Architecture Summary
- **Local Machine**: Initiates RDP brute force attempts via public IP
- **Azure Windows VM**: Target system that logs failed login attempts (Event ID 4625)
- **Azure Monitor Agent (AMA)**: Collects and forwards logs to Azure
- **Log Analytics Workspace**: Centralized log storage
- **Microsoft Sentinel**: Cloud-native SIEM that analyzes logs and triggers alerts
- **Custom Analytic Rule**: Detects brute force patterns using KQL
- **Incident Alert**: Medium-severity alert generated upon detection

<img width="800" height="536" alt="image" src="https://github.com/user-attachments/assets/48c10f18-42e3-4e7e-b083-c6e21cc9da02" />


**Figure 1: Architecture of the Brute Force Detection Lab**  
Visual flow from attack simulation to incident alert in Sentinel.

## 🛠️ Tools & Technologies
- Microsoft Azure  
- Microsoft Sentinel  
- Azure Monitor Agent (AMA)  
- Windows Virtual Machine  
- Kusto Query Language (KQL)

## 🔍 Detection Logic

### Custom Analytic Rule (KQL)
```kql
SecurityEvent
| where EventID == 4625
| summarize count() by IpAddress, bin(TimeGenerated, 5m)
| where count_ > 5
| extend Computer = computer, IpAddress = IpAddress, Account = Account
