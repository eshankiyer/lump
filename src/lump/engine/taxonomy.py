"""Framework references attached to findings.

Every finding carries ids from MITRE ATLAS (adversarial AI), MITRE ATT&CK
(classic intrusion tradecraft) and the OWASP Top 10 lists for LLM and agentic
applications, so detections map straight onto the frameworks auditors and SOC
teams already report against.
"""

ATLAS = {
    "AML.T0010": "AI Supply Chain Compromise",
    "AML.T0024": "Exfiltration via AI Inference API",
    "AML.T0025": "Exfiltration via Cyber Means",
    "AML.T0043": "Craft Adversarial Data",
    "AML.T0048": "External Harms",
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0053": "LLM Plugin Compromise / AI Agent Tool Invocation",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0056": "Extract LLM System Prompt",
    "AML.T0057": "LLM Data Leakage",
}

ATTACK = {
    "T1003": "OS Credential Dumping",
    "T1021": "Remote Services",
    "T1027": "Obfuscated Files or Information",
    "T1041": "Exfiltration Over C2 Channel",
    "T1053": "Scheduled Task/Job",
    "T1055": "Process Injection",
    "T1056.001": "Input Capture: Keylogging",
    "T1059": "Command and Scripting Interpreter",
    "T1070": "Indicator Removal",
    "T1098.004": "Account Manipulation: SSH Authorized Keys",
    "T1105": "Ingress Tool Transfer",
    "T1195": "Supply Chain Compromise",
    "T1218": "System Binary Proxy Execution",
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1496": "Resource Hijacking",
    "T1543": "Create or Modify System Process",
    "T1547.001": "Boot or Logon Autostart: Registry Run Keys / Startup Folder",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1552": "Unsecured Credentials",
    "T1555": "Credentials from Password Stores",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1567": "Exfiltration Over Web Service",
    "T1571": "Non-Standard Port",
}

OWASP = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory and Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}


def describe(ref: str) -> str:
    return ATLAS.get(ref) or ATTACK.get(ref) or OWASP.get(ref) or ref
