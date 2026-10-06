# Correlation and Timeline

## Process and network correlation

```kusto
DeviceProcessEvents
| where DeviceName == "FIN-LT-22"
| where Timestamp between (datetime(2026-08-09 09:10:00) .. datetime(2026-08-09 09:15:00))
| project ProcessTime=Timestamp, DeviceName, FileName,
          ProcessCommandLine, ProcessId
| join kind=inner (
    DeviceNetworkEvents
    | where DeviceName == "FIN-LT-22"
    | where Timestamp between (datetime(2026-08-09 09:10:00) .. datetime(2026-08-09 09:15:00))
    | project NetworkTime=Timestamp, DeviceName,
              InitiatingProcessFileName, RemoteIP, RemotePort
) on DeviceName
| where FileName == InitiatingProcessFileName
| project ProcessTime, NetworkTime, DeviceName, FileName,
          ProcessCommandLine, RemoteIP, RemotePort
| sort by ProcessTime asc
```

For a real hunt I would tighten the correlation with process identifiers where the available schema supports them instead of depending only on device and filename.

## Timeline

| Time (ET) | Event |
| --- | --- |
| 9:10 AM | `Invoice_August.docm` received by email |
| 9:12:04 AM | Word opens the document |
| 9:12:18 AM | Word launches hidden encoded PowerShell |
| 9:12:24 AM | PowerShell launches rundll32, which loads `cachetmp.dll` |
| 9:12:31 AM | PowerShell connects to 203.0.113.84:443 |
| 9:12:35 AM | rundll32 connects to the same address |
| 9:16 AM | Normal successful Microsoft 365 activity from New York / FIN-LT-22 |
| 9:27 AM | Failed sign-in from Netherlands / unknown Linux device |
| 9:29 AM | Second failed sign-in from the same unfamiliar source |

The endpoint events form a tight sequence. The identity attempts happened later and are worth investigating, but correlation by time alone is not enough to prove they are part of the same activity.
