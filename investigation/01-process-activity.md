# Process Activity

I started with the finance laptop because the hunting hypothesis centered on suspicious PowerShell launched from an Office process.

## KQL

```kusto
DeviceProcessEvents
| where Timestamp between (datetime(2026-08-09 09:10:00) .. datetime(2026-08-09 09:15:00))
| where DeviceName == "FIN-LT-22"
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, FileName, ProcessCommandLine
| sort by Timestamp asc
```

## Relevant events

| Time (ET) | Parent | Process | Detail |
| --- | --- | --- | --- |
| 9:12:04 AM | OUTLOOK.EXE | WINWORD.EXE | Opened `Invoice_August.docm` |
| 9:12:18 AM | WINWORD.EXE | powershell.exe | Hidden window with encoded command |
| 9:12:24 AM | powershell.exe | rundll32.exe | Loaded `cachetmp.dll` from the user's Temp directory |

## Analysis

PowerShell by itself is not enough to call activity malicious. The context is what made this sequence stand out.

Word spawned PowerShell with `-NoProfile`, `-WindowStyle Hidden`, and `-EncodedCommand`. Seconds later, PowerShell launched rundll32 and loaded a DLL from a user-writable Temp path.

The supplied data does not include a malware verdict for the document or DLL, so I treated the chain as suspicious rather than confirmed malware.

A separate PowerShell event on IT-LT-07 used PowerShell ISE to run `Get-Service`. That activity was not part of the suspicious process chain and appeared consistent with normal administrative work in the supplied context.
