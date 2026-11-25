# LanPulse AI Security Agent

## Purpose

AI is an intelligence layer across LanPulse, not a separate chatbot. It correlates threat-map activity, honeypot behavior, captured malware, vulnerability findings, and available runtime telemetry. The AI must distinguish observed facts from interpretation and preserve the source of each finding.

## Current capabilities

### Complete evidence for investigations

When a user explicitly asks the AI to investigate honeypot activity or a threat IP, LanPulse gathers all retained records for the relevant investigation:

- Built-in honeypot hits, raw event data, attempted usernames and passwords
- Cowrie sessions, including all recorded login attempts, commands, file transfers, decoded fragments, and reconstructed timelines
- Captured sample metadata, hashes, strings, decoded content, static analysis, cached YARA results, and available runtime telemetry
- Raw attack-log events and credential details associated with the selected source IP
- Related campaign correlations, cached threat intelligence, and affected LAN device scan/vulnerability evidence

The regular dashboard continues to use compact, bounded queries. Full evidence retrieval happens on demand for AI analysis so the Threat Map and honeypot views do not have to load every record just to render.

### Malware analyst

Each captured sample has an AI analysis action. It supplies the sample's static analysis and YARA findings, every linked honeypot session, related campaign evidence, and available sample-linked runtime events. It can explain likely capabilities, indicators, confidence, unknowns, and defensive actions.

Captured files are never executed by this feature. A YARA match is a rule match, not automatic proof of maliciousness. A string embedded in a file is not proof of a network connection, and a command entered into a Cowrie decoy is not proof that it ran on a real machine.

### Threat investigation and active scans

Threat Map AI investigations include raw attack history, honeypot evidence, captured samples, and information about LAN devices the source reached.

The user can explicitly request an Nmap or OpenVAS scan against one of those affected private LAN devices. The scan control:

- Requires LanPulse dashboard authentication
- Lists only private LAN devices recorded as targets of the selected source
- Requires the user to choose a scanner and confirm the action
- Rejects public IPs, unrelated devices, offline devices, and IP-conflicted targets
- Records the requested scan in the LanPulse event history

The public threat-source IP is never scanned by this workflow. Scanning arbitrary third-party systems is not an authorized use case.

## Evidence handling and privacy

- Attempted credentials and raw event details are included in AI evidence; they are not silently filtered out.
- Attacker-controlled strings, commands, hostnames, and file content are treated as untrusted evidence, never as instructions to the model or application.
- Local Ollama is recommended for sensitive evidence. If a cloud provider is selected, the evidence supplied to the AI—including attempted credentials and raw session details—is sent to that provider.
- The local Ollama context is configured for 32,768 tokens. If the complete evidence pack is too large, LanPulse returns an explicit context-size error rather than silently truncating the evidence. Very large investigations will need the planned retrieval/chunking workflow.

## Planned next stages

1. **Tool-using investigation agent:** let AI request focused evidence lookups, correlate records, and prepare scan plans; require explicit user approval for active operations.
2. **Large-evidence retrieval:** add pagination/chunking so very large histories can be analyzed in stages without dropping records or overwhelming the model context.
3. **Cross-source campaign graph:** connect attacker IPs, sessions, credentials, commands, malware hashes, YARA rules, runtime events, domains, and affected devices with evidence provenance.
4. **Investigation history:** persist analyst questions, evidence snapshots, scan jobs, results, and decisions so investigations can be resumed and compared.
5. **Isolated malware detonation:** evaluate a disposable, network-restricted sandbox for dynamic analysis. Never execute captured samples on the LanPulse host or the AI server itself.

These future stages are not represented as completed features until they are implemented and tested.
