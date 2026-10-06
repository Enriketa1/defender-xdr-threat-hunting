# Network and Identity Activity

## Network hunt

```kusto
DeviceNetworkEvents
| where Timestamp between (datetime(2026-08-09 09:10:00) .. datetime(2026-08-09 09:15:00))
| where DeviceName == "FIN-LT-22"
| project Timestamp, DeviceName,
          InitiatingProcessFileName, RemoteIP, RemotePort, ActionType
| sort by Timestamp asc
```

### Relevant network events

| Time (ET) | Process | Remote address | Port |
| --- | --- | --- | --- |
| 9:12:31 AM | powershell.exe | 203.0.113.84 | 443 |
| 9:12:35 AM | rundll32.exe | 203.0.113.84 | 443 |

Both processes in the suspicious chain connected to the same external address within seconds of execution. This strengthens the endpoint hypothesis, but the supplied dataset does not provide a malicious reputation verdict for the address.

## Identity hunt

```kusto
IdentityLogonEvents
| where Timestamp between (datetime(2026-08-09 08:30:00) .. datetime(2026-08-09 10:00:00))
| where AccountName == "maya.chen"
| project Timestamp, AccountName, ActionType,
          DeviceName, IPAddress, Location
| sort by Timestamp asc
```

The user had normal successful New York activity at 8:41 AM and 9:16 AM from FIN-LT-22. At 9:27 AM and 9:29 AM, two failed attempts appeared from the Netherlands on an unknown Linux device with MFA not satisfied.

The timing makes the failed attempts relevant, but I would not claim that credentials were stolen. There was no successful Netherlands sign-in in the supplied data and no evidence directly connecting those attempts to the earlier endpoint activity.
