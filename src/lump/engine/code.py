"""Malicious-behaviour heuristics for AI-generated scripts, commands and artifacts.

This is a *detector*: it scans text (model output containing code, a command an
agent wants to run, or a script file on disk) and reports indicators of
high-risk behaviour so a policy can warn or block before anything executes. It
does not generate, assemble or run any of these techniques — every rule is a
read-only signature keyed to behaviour, mapped to MITRE ATT&CK so findings slot
into existing SOC reporting.

Rules deliberately match short, characteristic tokens (tool names, API symbols,
well-known flag combinations) rather than full working command lines, which
keeps the signatures compact and avoids shipping runnable attack recipes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .types import Finding, Severity, snippet


@dataclass(frozen=True)
class CodeRule:
    id: str
    title: str
    category: str
    pattern: str
    severity: Severity
    attack: tuple[str, ...] = ()


S = Severity

# Each pattern is a detection signature. They are intentionally partial — they
# recognise the hallmark of a technique, not a complete payload.
CODE_RULES: tuple[CodeRule, ...] = (
    CodeRule("CODE-001", "Remote download piped directly into an interpreter", "execution.download_exec",
             r"\b(?:curl|wget|fetch)\b[^\n|;]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b|\b(?:curl|wget)\b[^\n;]{0,200}\|\s*(?:sudo\s+)?python[0-9.]*\b",
             S.HIGH, ("T1105", "T1059")),
    CodeRule("CODE-002", "Scripted download-and-run cradle", "execution.download_exec",
             r"\b(?:iex|invoke-expression)\b[\s\S]{0,80}?(?:downloadstring|downloadfile|invoke-webrequest|iwr|irm|net\.webclient)",
             S.HIGH, ("T1105", "T1059")),
    CodeRule("CODE-003", "Interpreter invoked with an encoded command blob", "defense_evasion.encoded_command",
             r"\bpowershell(?:\.exe)?\b[^\n]{0,80}\s-(?:e|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+/=]{20,}",
             S.HIGH, ("T1027", "T1059")),
    CodeRule("CODE-004", "Decode-then-evaluate of an opaque blob", "defense_evasion.decode_exec",
             r"\b(?:exec|eval)\s*\(\s*(?:base64\.b64decode|codecs\.decode|bytes\.fromhex|zlib\.decompress|marshal\.loads|atob)\s*\(|\beval\s*\(\s*(?:atob|unescape|String\.fromCharCode)\s*\(|FromBase64String[\s\S]{0,80}?(?:Invoke-Expression|iex|Assembly\]::Load)",
             S.HIGH, ("T1027", "T1059")),
    CodeRule("CODE-005", "Signed-binary proxy execution of remote content", "execution.lolbin",
             r"\b(?:certutil(?:\.exe)?\s+[^\n]{0,40}-urlcache|bitsadmin(?:\.exe)?\s+/transfer|mshta(?:\.exe)?\s+(?:https?:|vbscript:|javascript:)|regsvr32(?:\.exe)?\s+[^\n]{0,40}/i:\s*https?:|rundll32(?:\.exe)?\s+[^\n]{0,20}javascript:)",
             S.HIGH, ("T1218", "T1105")),
    CodeRule("CODE-010", "Interactive socket back to a remote host", "command_and_control.reverse_shell",
             r"/dev/(?:tcp|udp)/[\w.\-]+/\d+|\bnc(?:at)?\b[^\n]{0,60}\s-[a-z]*e\s*(?:/bin/)?(?:ba|z)?sh\b|\bsocat\b[^\n]{0,80}exec:|New-Object\s+System\.Net\.Sockets\.TCPClient[\s\S]{0,400}?(?:GetStream|iex)|\bmkfifo\b[^\n]{0,80}\bnc\b",
             S.CRITICAL, ("T1059", "T1571")),
    CodeRule("CODE-011", "Beacon to a messaging or paste/tunnel service", "exfiltration.web_service",
             r"api\.telegram\.org/bot|discord(?:app)?\.com/api/webhooks|hooks\.slack\.com/services|pastebin\.com/api|transfer\.sh|file\.io|0x0\.st|webhook\.site|requestbin|pipedream\.net|ngrok(?:-free)?\.(?:io|app)|interact\.sh|oast\.(?:pro|live|fun|me|site|online)",
             S.MEDIUM, ("T1567",)),
    CodeRule("CODE-012", "Local files pushed to a remote endpoint", "exfiltration.file_upload",
             r"\bcurl\b[^\n]{0,200}(?:-F\s*[\"']?\w*=@|--data-binary\s+@|-d\s+@|-T\s+\S)|\bscp\b[^\n]{0,120}\s\S+@[\w.\-]+:|\brsync\b[^\n]{0,120}\s\S+@[\w.\-]+:|Invoke-RestMethod[^\n]{0,200}-InFile",
             S.MEDIUM, ("T1041", "T1567")),
    CodeRule("CODE-020", "Reference to a credential-dumping tool", "credential_access.dumping",
             r"\b(?:mimikatz|sekurlsa::|lsadump::|kerberos::golden|procdump(?:64)?|lazagne|secretsdump|hashdump|pypykatz|nanodump)\b",
             S.CRITICAL, ("T1003",)),
    CodeRule("CODE-021", "Access to credential stores or secret files", "credential_access.files",
             r"\.(?:ssh/id_(?:rsa|ed25519|ecdsa|dsa)|aws/credentials|git-credentials|netrc|pgpass|docker/config\.json|kube/config)\b|/etc/shadow\b|security\s+(?:find|dump)-(?:generic|internet)-password|\bdump-keychain\b|CredEnumerate|vaultcmd\s+/list",
             S.HIGH, ("T1552", "T1555")),
    CodeRule("CODE-022", "Keystroke-capture API usage", "collection.keylogging",
             r"pynput\.keyboard\.Listener|keyboard\.on_press|SetWindowsHookEx\w*\s*\(\s*(?:WH_KEYBOARD_LL|13)\b|GetAsyncKeyState\s*\(|CGEventTapCreate[\s\S]{0,200}?kCGEventKeyDown",
             S.HIGH, ("T1056.001",)),
    CodeRule("CODE-030", "Write to an autostart registry Run key", "persistence.registry_run",
             r"(?:HKCU|HKLM|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)[\\:/]+Software[\\/]+Microsoft[\\/]+Windows[\\/]+CurrentVersion[\\/]+Run(?:Once)?\b",
             S.HIGH, ("T1547.001",)),
    CodeRule("CODE-031", "Scheduled-task or cron persistence", "persistence.scheduled_task",
             r"\bschtasks(?:\.exe)?\s+/create\b|@reboot\s+\S|\becho\b[^\n]{0,200}>>?\s*/etc/cron|Register-ScheduledTask",
             S.MEDIUM, ("T1053",)),
    CodeRule("CODE-032", "Append to SSH authorized_keys", "persistence.ssh_keys",
             r"(?:>>|tee\s+-a)\s*[^\n]{0,40}\.ssh/authorized_keys", S.HIGH, ("T1098.004",)),
    CodeRule("CODE-033", "System service or launch-agent install", "persistence.service",
             r"/etc/systemd/system/[\w.\-]+\.service|Library/Launch(?:Agents|Daemons)/[\w.\-]+\.plist|\bsc(?:\.exe)?\s+create\s+\w+\s+binpath=|New-Service\s+-Name",
             S.MEDIUM, ("T1543",)),
    CodeRule("CODE-034", "Append to a shell startup profile", "persistence.shell_profile",
             r"(?:>>|tee\s+-a)\s*(?:~|\$HOME)/\.(?:bashrc|zshrc|profile|bash_profile|zprofile)\b", S.MEDIUM, ("T1547.001",)),
    CodeRule("CODE-040", "Disabling or excluding endpoint security tooling", "defense_evasion.disable_security",
             r"Set-MpPreference\s+[^\n]{0,40}-Disable\w*\s+\$?(?:true|1)|Add-MpPreference\s+-ExclusionPath|\bAmsiUtils\b|amsiInitFailed|\bsetenforce\s+0\b|\bsystemctl\s+(?:stop|disable)\s+(?:auditd|falcon|crowdstrike|sentinel|osqueryd|wazuh)",
             S.HIGH, ("T1562.001",)),
    CodeRule("CODE-041", "Clearing logs or shell history", "defense_evasion.indicator_removal",
             r"\b(?:history\s+-c|rm\s+-f\s+[^\n]{0,40}\.bash_history|Clear-EventLog|wevtutil\s+cl\b|>\s*/var/log/\w+|journalctl\s+--vacuum-time=1s)\b",
             S.MEDIUM, ("T1070",)),
    CodeRule("CODE-050", "Destructive mass deletion", "impact.destruction",
             r"\brm\s+-rf\s+(?:--no-preserve-root\s+)?/(?:\s|\*|$)|\bdd\s+if=/dev/(?:zero|u?random)\s+of=/dev/[sv]d[a-z]\b|\bmkfs\.\w+\s+/dev/[sv]d[a-z]|Remove-Item[^\n]{0,40}-Recurse[^\n]{0,40}-Force[^\n]{0,20}C:\\",
             S.HIGH, ("T1485",)),
    CodeRule("CODE-051", "Ransomware-style bulk encryption", "impact.ransomware",
             r"\bfor\b[^\n]{0,80}\bin\b[^\n]{0,80}\b(?:glob|rglob|os\.walk|Get-ChildItem)\b[\s\S]{0,300}?(?:AES\.new|Fernet\(|Cipher\(|\.encrypt\(|gpg\s+-c)[\s\S]{0,200}?(?:os\.remove|unlink|Remove-Item|\.unlink\()",
             S.HIGH, ("T1486",)),
    CodeRule("CODE-052", "Shadow-copy or backup deletion", "impact.inhibit_recovery",
             r"\bvssadmin(?:\.exe)?\s+delete\s+shadows|\bwbadmin\s+delete\s+catalog|bcdedit[^\n]{0,60}recoveryenabled\s+no|Get-WmiObject[^\n]{0,40}Win32_Shadowcopy[\s\S]{0,40}Delete",
             S.HIGH, ("T1490",)),
    CodeRule("CODE-053", "Cryptomining pool connection", "impact.resource_hijacking",
             r"\b(?:xmrig|minerd|cpuminer|ethminer|cgminer|nbminer)\b|stratum\+(?:tcp|ssl)://|--coin\s+monero\b|pool\.(?:minexmr|supportxmr|nanopool|hiveon)\b",
             S.MEDIUM, ("T1496",)),
    CodeRule("CODE-060", "Privilege-escalation primitive", "privilege_escalation.suid",
             r"\bchmod\s+(?:[0-7]*[46]7[0-7]{2}|u\+s|\+s)\s|\bsetcap\s+cap_setuid|cp\s+/bin/(?:ba)?sh\s+[^\n]{0,40}&&\s*chmod\s+\+s|pkexec[^\n]{0,40}(?:CVE|PwnKit)",
             S.MEDIUM, ("T1548",)),
)

_COMPILED: list[tuple[CodeRule, re.Pattern[str]]] = [
    (rule, re.compile(rule.pattern, re.IGNORECASE)) for rule in CODE_RULES
]

# Trusted public package name prefixes used by the slopsquat check below.
_POPULAR_PACKAGES = frozenset(
    {
        "requests", "numpy", "pandas", "flask", "django", "fastapi", "pytest", "scipy", "boto3", "pillow",
        "urllib3", "pyyaml", "click", "tqdm", "matplotlib", "torch", "tensorflow", "scikit-learn", "sklearn",
        "openai", "anthropic", "langchain", "transformers", "aiohttp", "sqlalchemy", "pydantic", "cryptography",
        "express", "react", "lodash", "axios", "webpack", "typescript", "eslint", "chalk", "commander", "dotenv",
        "next", "vue", "jest", "vite", "zod", "prisma", "nestjs", "socket.io",
    }
)

_INSTALL_RE = re.compile(
    r"\b(?:pip[0-9.]*\s+install|pip3?\s+install|python\s+-m\s+pip\s+install|npm\s+(?:i|install|add)|yarn\s+add|pnpm\s+add|gem\s+install|cargo\s+add)\b([^\n&|;]{1,300})",
    re.IGNORECASE,
)
_PACKAGE_TOKEN_RE = re.compile(r"(?:^|\s)(@?[A-Za-z0-9][A-Za-z0-9._\-]{0,99})")


def _typo_close(a: str, b: str) -> bool:
    """True when ``a`` and ``b`` are within one Damerau edit (insert, delete,
    substitute, or a single adjacent transposition). Transpositions matter here
    because ``reqeusts`` for ``requests`` is a classic typosquat."""

    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diffs = [i for i, (x, y) in enumerate(zip(a, b, strict=False)) if x != y]
        if len(diffs) == 1:
            return True
        if len(diffs) == 2 and diffs[1] == diffs[0] + 1:
            i, j = diffs
            return a[i] == b[j] and a[j] == b[i]  # adjacent transposition
        return False
    # One insertion/deletion: ensure a is the shorter string.
    if la > lb:
        a, b, la, lb = b, a, lb, la
    i = j = 0
    edited = False
    while i < la and j < lb:
        if a[i] == b[j]:
            i += 1
            j += 1
        elif edited:
            return False
        else:
            edited = True
            j += 1
    return True


def _normalise_package(token: str) -> str:
    token = token.strip().strip("\"'")
    if token.startswith("@"):
        scope_pkg = token[1:].split("@", 1)[0]
        return "@" + scope_pkg
    return re.split(r"[<>=!~\[;@]", token, maxsplit=1)[0].strip().lower()


class CodeDetector:
    name = "code"

    def __init__(self, extra_known_packages: frozenset[str] = frozenset()):
        self.known_packages = _POPULAR_PACKAGES | extra_known_packages

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for rule, regex in _COMPILED:
            match = regex.search(text)
            if match:
                findings.append(
                    Finding(
                        detector=self.name,
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        confidence=0.7,
                        category=rule.category,
                        evidence=snippet(text, *match.span()),
                        span=match.span(),
                        attack=rule.attack,
                        owasp=("ASI05", "LLM05"),
                        metadata={"framework": "att&ck"},
                    )
                )
        findings.extend(self._slopsquat(text))
        return findings

    def _slopsquat(self, text: str) -> list[Finding]:
        """Flag install commands naming packages that typosquat popular ones."""

        out: list[Finding] = []
        seen: set[str] = set()
        for install in _INSTALL_RE.finditer(text):
            args = install.group(1)
            for tok in _PACKAGE_TOKEN_RE.findall(args):
                if tok.startswith("-"):
                    continue
                name = _normalise_package(tok)
                if not name or len(name) < 3 or name in self.known_packages or name in seen:
                    continue
                seen.add(name)
                for known in self.known_packages:
                    if known.startswith("@"):
                        continue
                    if name != known and _typo_close(name, known):
                        out.append(
                            Finding(
                                detector=self.name,
                                rule_id="CODE-070",
                                title=f"Possible typosquat of '{known}' package",
                                severity=Severity.MEDIUM,
                                confidence=0.6,
                                category="supply_chain.typosquat",
                                evidence=f"install of '{name}' (vs '{known}')",
                                atlas=("AML.T0010",),
                                owasp=("LLM03", "ASI04"),
                                attack=("T1195",),
                                metadata={"package": name, "resembles": known},
                            )
                        )
                        break
        return out
