# Defender XDR Threat Hunting

A simulated threat-hunting exercise using Microsoft Defender XDR-style telemetry and KQL. The goal was to start with a hypothesis, correlate endpoint, network, and identity activity, and decide what the evidence actually supports.

The dataset is fictional. No production systems or employer data are included.

## Hunting hypothesis

A finance workstation may have executed suspicious PowerShell activity originating from an Office process and then communicated with an unfamiliar external address. Related identity activity may indicate whether the behavior was isolated to the endpoint or part of a broader account compromise.

## Investigation

I worked through the hunt in four parts:

1. [Process activity](investigation/01-process-activity.md)
2. [Network and identity activity](investigation/02-network-and-identity.md)
3. [Correlation and timeline](investigation/03-correlation-and-timeline.md)
4. [Findings and response](investigation/04-findings.md)

The KQL used during the exercise is also collected in [queries/hunting-queries.kql](queries/hunting-queries.kql).

## Key finding

The endpoint evidence was the strongest part of the hunt. An Office document was followed by hidden encoded PowerShell, rundll32 loading a DLL from the user's Temp directory, and outbound connections from both processes to the same external address.

Two failed foreign sign-ins occurred later. I kept them in scope because of the timing, but the supplied evidence does not prove credential theft or connect those attempts to the endpoint activity.

**Assessment:** High severity, medium-high confidence.

## ATT&CK mapping

- T1059.001 — PowerShell
- T1218.011 — Rundll32
- T1204.002 — Malicious File (hypothesis only; the file was not confirmed malicious)

## Scope note

This is an offline exercise based on fictional Defender XDR-style records. Queries document how I would investigate the supplied evidence; they were not executed against a live Microsoft Defender tenant.
