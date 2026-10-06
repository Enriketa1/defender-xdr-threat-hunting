# Findings and Response

## Assessment

**Severity:** High  
**Confidence:** Medium-High

The endpoint portion of the hunting hypothesis is strongly supported by the supplied evidence. Shortly after an Office document was opened, Word spawned hidden encoded PowerShell. PowerShell then launched rundll32, which loaded a DLL from the user's Temp directory. Both PowerShell and rundll32 communicated with the same external address over TCP 443.

The later failed Netherlands authentication attempts add concern but do not establish account compromise. No successful foreign sign-in or confirmed credential theft is present.

## What the evidence does not prove

I would not claim:

- confirmed malware
- confirmed command-and-control
- confirmed credential theft
- successful account compromise
- that the foreign sign-ins were caused by the endpoint activity

## ATT&CK mapping

| Behavior | Technique |
| --- | --- |
| PowerShell execution | T1059.001 — PowerShell |
| rundll32 execution | T1218.011 — Rundll32 |
| User opened suspicious Office document | T1204.002 — Malicious File (hypothesis only) |

## What I would investigate next

I would review additional file and endpoint telemetry for the Office document and DLL, safely available PowerShell telemetry, hashes and reputation data, other connections involving the external indicator, email-delivery details, other devices with matching indicators, and additional authentication/session evidence for the affected user.

## Recommended response

Based on the endpoint evidence, I would escalate the case for further investigation and recommend isolating the affected endpoint while evidence is preserved. I would also evaluate whether the user's sessions or credentials require containment and search for the same indicators elsewhere.

These are recommendations only. Isolation, blocking, session revocation, password resets, or other containment actions would follow the organization's authorization process.
