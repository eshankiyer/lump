"""Declarative pattern rules shared by the Python engine and the browser extension.

Rules are plain data so they can be exported to JSON (``lump export-rules``)
and executed by the extension's JavaScript detector. Patterns therefore stick
to the regex subset that behaves identically in Python ``re`` and ECMAScript:
no inline flags, no named groups, no possessive quantifiers. Case-insensitivity
is expressed through the ``flags`` field.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PatternRule:
    id: str
    title: str
    category: str
    pattern: str
    weight: float  # 0..1 contribution to the detector's score
    flags: str = "i"
    # Weight multiplier when the content is untrusted (tool output, web page ...).
    untrusted_boost: float = 1.0
    # Weight multiplier when the content comes straight from the user.
    trusted_factor: float = 1.0
    atlas: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    attack: tuple[str, ...] = ()
    tags: tuple[str, ...] = field(default=())

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "pattern": self.pattern,
            "flags": self.flags,
            "weight": self.weight,
            "untrusted_boost": self.untrusted_boost,
            "trusted_factor": self.trusted_factor,
            "atlas": list(self.atlas),
            "owasp": list(self.owasp),
        }


_PI = ("AML.T0051",)
_PI_D = ("AML.T0051", "AML.T0051.000")
_PI_I = ("AML.T0051", "AML.T0051.001")
_JB = ("AML.T0054",)
_SPE = ("AML.T0056",)

# Verb / object vocabularies reused across rules.
_OVERRIDE_VERBS = r"(?:ignore|disregard|forget|skip|bypass|override|overrule|discard|drop|neglect|abandon|set aside)"
_PRIOR = r"(?:previous|prior|above|earlier|preceding|foregoing|initial|original|old|existing|system|developer|safety)"
_INSTRUCTIONS = r"(?:instructions?|prompts?|rules?|directions?|directives?|guidelines?|guardrails?|context|commands?|constraints?|policies|policy|programming|restrictions?|safeguards?|messages?)"

INJECTION_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        "PI-001", "Instruction override", "prompt_injection.override",
        rf"\b{_OVERRIDE_VERBS}\b[\s\S]{{0,30}}?\b{_PRIOR}\b[\s\S]{{0,30}}?\b{_INSTRUCTIONS}\b",
        0.75, untrusted_boost=1.25, trusted_factor=0.8, atlas=_PI, owasp=("LLM01",),
    ),
    PatternRule(
        "PI-006", "Override of the assistant's own instructions", "prompt_injection.override",
        rf"\b{_OVERRIDE_VERBS}\s+(?:all\s+|any\s+)?(?:of\s+)?(?:your|its|the\s+(?:ai|assistant|model)'?s?)\s+(?:\w+\s+)?{_INSTRUCTIONS}\b",
        0.7, untrusted_boost=1.25, trusted_factor=0.8, atlas=_PI, owasp=("LLM01",),
    ),
    PatternRule(
        "PI-007", "Override of everything said before", "prompt_injection.override",
        rf"\b{_OVERRIDE_VERBS}\s+(?:everything|all|anything)\s+(?:you\s+(?:were|have\s+been|'?ve\s+been)\s+(?:told|instructed|given|taught)|(?:that\s+)?(?:was\s+)?(?:said|written|stated)?\s*(?:above|before|previously|so\s+far))",
        0.7, untrusted_boost=1.25, trusted_factor=0.8, atlas=_PI, owasp=("LLM01",),
    ),
    PatternRule(
        "PI-002", "Instructions declared void", "prompt_injection.override",
        r"\b(?:previous|prior|above|earlier|original|system|all)\s+(?:\w+\s+){0,2}?(?:instructions?|prompts?|rules?|guidelines?)\s+(?:are|is|were|have been)\s+(?:now\s+|hereby\s+)?(?:void|cancell?ed|revoked|obsolete|null|outdated|no longer (?:valid|apply|applicable|in effect))",
        0.7, untrusted_boost=1.25, atlas=_PI, owasp=("LLM01",),
    ),
    PatternRule(
        "PI-003", "Injected replacement instructions", "prompt_injection.override",
        r"(?:here\s+(?:are|is)\s+(?:your\s+|the\s+)?)?\b(?:new|updated|revised|real|actual|true|important|urgent|additional)\s+(?:system\s+)?(?:instructions?|orders|directives?|task|objective|prompt)\s*[:\-]",
        0.45, untrusted_boost=1.4, trusted_factor=0.7, atlas=_PI, owasp=("LLM01", "ASI01"),
    ),
    PatternRule(
        "PI-004", "Behaviour reprogramming", "prompt_injection.override",
        r"\bfrom\s+now\s+on\b[\s\S]{0,40}?\b(?:you\s+(?:will|must|shall|are|should|can)|always|never|only|respond|reply|answer|ignore)\b",
        0.4, untrusted_boost=1.4, trusted_factor=0.7, atlas=_PI, owasp=("LLM01",),
    ),
    PatternRule(
        "PI-005", "Stop / end of prompt marker", "prompt_injection.delimiter",
        r"(?:\bend\s+of\s+(?:the\s+)?(?:user\s+)?(?:input|prompt|instructions|document|context|text)\b|\bstop\s+(?:reading|processing|following)\b[\s\S]{0,20}\b(?:above|previous|instructions)\b)",
        0.45, untrusted_boost=1.3, atlas=_PI, owasp=("LLM01",),
    ),
    PatternRule(
        "PI-010", "Fake chat-template role token", "prompt_injection.delimiter",
        r"(?:<\|(?:im_start|im_end|system|user|assistant|endoftext|start_header_id|end_header_id|eot_id)\|>|\[/?INST\]|<<\/?SYS>>|<\/?(?:system|sys|system_prompt|instructions?)>)",
        0.7, flags="i", untrusted_boost=1.2, atlas=_PI, owasp=("LLM01",),
    ),
    PatternRule(
        "PI-011", "Spoofed conversation turn", "prompt_injection.delimiter",
        r"(?:^|\n)\s*(?:#{1,6}\s*)?(?:system|assistant|developer)\s*(?:message|prompt)?\s*:\s*\S",
        0.4, untrusted_boost=1.5, trusted_factor=0.6, atlas=_PI, owasp=("LLM01",),
    ),
    PatternRule(
        "PI-012", "Spoofed role object", "prompt_injection.delimiter",
        r"[\"']role[\"']\s*:\s*[\"'](?:system|developer)[\"']",
        0.45, untrusted_boost=1.4, trusted_factor=0.5, atlas=_PI, owasp=("LLM01",),
    ),
    PatternRule(
        "PI-020", "Message addressed to the AI", "prompt_injection.indirect",
        r"\b(?:dear|attention|note|message|instructions?|hey|hi|hello|important)\s+(?:to|for)\s+(?:the\s+)?(?:ai|a\.i\.|llm|assistant|chatbot|language model|ai agent|agent|model|copilot|gpt|claude|gemini|bot)s?\b",
        0.45, untrusted_boost=1.6, trusted_factor=0.4, atlas=_PI_I, owasp=("LLM01", "ASI01"),
    ),
    PatternRule(
        "PI-021", "Conditional trigger on AI readers", "prompt_injection.indirect",
        r"\bif\s+you\s+are\s+(?:an?\s+)?(?:ai|a\.i\.|llm|large language model|language model|assistant|chatbot|ai agent|automated|bot|gpt|claude|gemini)\b",
        0.6, untrusted_boost=1.4, trusted_factor=0.5, atlas=_PI_I, owasp=("LLM01", "ASI01"),
    ),
    PatternRule(
        "PI-022", "Concealment from the user", "prompt_injection.indirect",
        r"\b(?:do\s+not|don'?t|never|without)\s+(?:tell(?:ing)?|inform(?:ing)?|mention(?:ing)?|reveal(?:ing)?|alert(?:ing)?|notify(?:ing)?|let(?:ting)?|show(?:ing)?|disclos(?:e|ing))\s+(?:this\s+(?:to\s+)?|it\s+to\s+|anything\s+to\s+)?(?:the\s+)?(?:user|human|operator|reader|customer|victim|them)\b",
        0.6, untrusted_boost=1.4, trusted_factor=0.6, atlas=_PI_I, owasp=("LLM01", "ASI01", "ASI09"),
    ),
    PatternRule(
        "PI-023", "Covert action request", "prompt_injection.indirect",
        r"\b(?:secretly|silently|covertly|quietly|discreetly|invisibly|without\s+(?:the\s+)?(?:user|human|anyone)(?:'s)?\s+(?:knowing|knowledge|noticing|consent|permission))\b",
        0.4, untrusted_boost=1.5, trusted_factor=0.6, atlas=_PI_I, owasp=("LLM01", "ASI01"),
    ),
    PatternRule(
        "PI-024", "Instruction to change the summary/answer", "prompt_injection.indirect",
        r"\b(?:when|if)\s+(?:asked|summari[sz]ing|reviewing|evaluating|analy[sz]ing|reading|processing)\b[\s\S]{0,60}?\b(?:say|state|respond|reply|output|claim|recommend|rate|answer|include)\b",
        0.35, untrusted_boost=1.6, trusted_factor=0.4, atlas=_PI_I, owasp=("LLM01", "ASI01", "LLM09"),
    ),
    PatternRule(
        "PI-030", "Exfiltration instruction", "prompt_injection.exfiltration",
        r"\b(?:send|post|upload|forward|transmit|exfiltrate|leak|email|e-mail|submit|append|encode|include)\b[\s\S]{0,60}?\b(?:conversation|chat history|history|password|credentials?|secrets?|api[ _-]?keys?|tokens?|cookies?|session|system prompt|private|personal|data|files?|contents?|emails?)\b[\s\S]{0,60}?(?:https?://|\bto\s+(?:this\s+)?(?:url|endpoint|webhook|server|address|email)\b|@[a-z0-9-]+\.[a-z]{2,})",
        0.6, untrusted_boost=1.4, trusted_factor=0.6, atlas=("AML.T0051", "AML.T0057", "AML.T0025"), owasp=("LLM01", "LLM02"),
    ),
    PatternRule(
        "PI-031", "Markdown/image beacon instruction", "prompt_injection.exfiltration",
        r"!\[[^\]]{0,100}\]\(\s*https?://[^)\s]{1,300}(?:\{|\$|%7B|<)[^)\s]{0,200}\)",
        0.6, untrusted_boost=1.4, atlas=("AML.T0051", "AML.T0057", "AML.T0025"), owasp=("LLM01", "LLM05"),
    ),
    PatternRule(
        "PI-032", "Instruction to visit attacker URL with data", "prompt_injection.exfiltration",
        r"\b(?:visit|open|browse|fetch|load|navigate\s+to|call|request|curl|wget|click)\b[\s\S]{0,40}?https?://[^\s\"')]+[?&][a-z0-9_]{1,20}=(?:\{|\$|%7B|<|\[)",
        0.55, untrusted_boost=1.4, atlas=("AML.T0051", "AML.T0025"), owasp=("LLM01", "ASI02"),
    ),
    PatternRule(
        "PI-040", "Tool / action coercion", "prompt_injection.tool_coercion",
        r"\b(?:you\s+must|immediately|now|first|then|please)\s+(?:call|invoke|use|run|execute|trigger)\s+(?:the\s+)?[\w.\-]{2,40}\s+(?:tool|function|command|action|plugin|api)\b",
        0.35, untrusted_boost=1.7, trusted_factor=0.3, atlas=("AML.T0051", "AML.T0053"), owasp=("LLM01", "LLM06", "ASI02"),
    ),
    PatternRule(
        "PI-041", "Instruction to run commands", "prompt_injection.tool_coercion",
        r"\b(?:run|execute|eval(?:uate)?|paste)\s+(?:this|the\s+following|these)\s+(?:command|commands|code|script|snippet|in\s+(?:your|the)\s+terminal)\b",
        0.3, untrusted_boost=1.8, trusted_factor=0.2, atlas=("AML.T0051", "AML.T0053"), owasp=("LLM01", "ASI05"),
    ),
    PatternRule(
        "PI-042", "Credential / secret harvesting", "prompt_injection.tool_coercion",
        r"\b(?:read|open|cat|print|show|list|get|retrieve|collect|find|search\s+for)\b[\s\S]{0,40}?(?:~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.env\b|/etc/(?:passwd|shadow)|\.git-credentials|\.npmrc|\.pypirc|\.netrc|kubeconfig|\.docker/config\.json|keychain|password\s+manager|browser\s+(?:passwords|cookies))",
        0.55, untrusted_boost=1.5, trusted_factor=0.5, atlas=("AML.T0051", "AML.T0053"), owasp=("LLM01", "LLM06", "ASI02"), attack=("T1552",),
    ),
    PatternRule(
        "JB-001", "Unrestricted persona jailbreak", "jailbreak.persona",
        r"\b(?:you\s+are\s+(?:now\s+)?|act\s+as\s+|pretend\s+(?:to\s+be|you\s+are)\s+|roleplay\s+as\s+|become\s+)(?:an?\s+)?(?:dan\b|stan\b|dude\b|aim\b|evil|unfiltered|uncensored|unrestricted|unlimited|jailbroken|amoral|unethical|unbound|rogue|developer\s+mode|god\s*mode|sudo\s+mode)",
        0.7, atlas=_JB, owasp=("LLM01",),
    ),
    PatternRule(
        "JB-002", "Do Anything Now", "jailbreak.persona",
        r"\bdo\s+anything\s+now\b|\bDAN\s+(?:mode|prompt|jailbreak)\b|\bjailbreak(?:en|ed|ing)?\s+(?:mode|prompt|enabled|activated)\b",
        0.8, atlas=_JB, owasp=("LLM01",),
    ),
    PatternRule(
        "JB-003", "Request to drop safety restrictions", "jailbreak.restriction_removal",
        r"\b(?:without|no|free\s+(?:of|from)|ignore|remove|disable|turn\s+off|bypass|lift|suspend|unlock)\s+(?:any\s+|all\s+|your\s+|the\s+)*(?:(?:ethical|moral|safety|content)[,\s]+(?:or\s+|and\s+)?)*(?:restrictions?|filters?|filtering|limitations?|guidelines?|guardrails?|safeguards?|censorship|safety\s+(?:rules|measures|protocols)|content\s+polic(?:y|ies)|moral(?:s|ity)|ethics)\b",
        0.5, atlas=_JB, owasp=("LLM01",),
    ),
    PatternRule(
        "JB-004", "Developer / debug mode activation", "jailbreak.mode_switch",
        r"\b(?:enable|activate|enter|switch\s+(?:to|into)|turn\s+on|engage)\s+(?:the\s+)?(?:developer|dev|debug|maintenance|admin|god|sudo|root|unrestricted|test)\s+mode\b",
        0.6, atlas=_JB, owasp=("LLM01",),
    ),
    PatternRule(
        "JB-005", "Dual-response jailbreak format", "jailbreak.persona",
        r"\b(?:two|2|dual|both)\s+(?:different\s+)?(?:responses|answers|replies|outputs)\b[\s\S]{0,120}?\b(?:unfiltered|jailbroken|uncensored|unrestricted|without\s+restrictions|dan|developer\s+mode|normal\s+and)\b",
        0.55, atlas=_JB, owasp=("LLM01",),
    ),
    PatternRule(
        "JB-006", "Refusal suppression", "jailbreak.refusal_suppression",
        r"\b(?:never|do\s+not|don'?t|must\s+not|cannot|can'?t)\s+(?:refuse|decline|say\s+(?:no|you\s+can'?t|i\s+can'?t|sorry)|apologi[sz]e|add\s+(?:disclaimers?|warnings?)|break\s+character|mention\s+(?:openai|anthropic|your\s+(?:guidelines|policies)))",
        0.45, atlas=_JB, owasp=("LLM01",),
    ),
    PatternRule(
        "JB-007", "Fictional / hypothetical framing to evade safety", "jailbreak.framing",
        r"\b(?:hypothetically|in\s+a\s+(?:fictional|hypothetical|imaginary)\s+(?:world|scenario|universe|story)|for\s+(?:a\s+)?(?:novel|story|screenplay|movie)|purely\s+(?:educational|hypothetical))\b[\s\S]{0,120}?\b(?:no\s+(?:rules|laws|restrictions|ethics|limits)|illegal|unrestricted|without\s+(?:restrictions|limits|consequences)|anything\s+goes)\b",
        0.4, atlas=_JB, owasp=("LLM01",),
    ),
    PatternRule(
        "JB-008", "Token-smuggling / obfuscated instruction request", "jailbreak.obfuscation",
        r"\b(?:decode|decipher|translate|interpret)\s+(?:this|the\s+following)\s+(?:base64|hex|rot13|binary|morse|cipher|encoded)\b[\s\S]{0,60}?\b(?:and|then)\s+(?:follow|execute|obey|do|carry\s+out|act\s+on)\b",
        0.6, atlas=("AML.T0054", "AML.T0051"), owasp=("LLM01",),
    ),
    PatternRule(
        "SP-001", "System prompt extraction", "prompt_extraction",
        r"\b(?:reveal|show|print|display|output|repeat|recite|leak|dump|disclose|tell\s+me|give\s+me|what\s+(?:is|are|was|were))\s+(?:me\s+)?(?:your|the)\s+(?:full\s+|complete\s+|entire\s+|exact\s+|original\s+|initial\s+|hidden\s+|secret\s+|internal\s+)*(?:system\s+(?:prompt|message|instructions?)|initial\s+(?:prompt|instructions?)|hidden\s+(?:prompt|instructions?)|developer\s+(?:prompt|message|instructions?)|instructions\s+you\s+(?:were|have\s+been)\s+given|pre-?prompt|meta[- ]?prompt)",
        0.65, atlas=_SPE, owasp=("LLM07",),
    ),
    PatternRule(
        "SP-002", "Verbatim repeat of preceding context", "prompt_extraction",
        r"\b(?:repeat|print|output|copy|recite|echo)\s+(?:all\s+(?:of\s+)?|everything\s+|the\s+)?(?:the\s+)?(?:text|words|content|everything|lines?|tokens?|message)\s+(?:above|before\s+this|prior\s+to\s+this|that\s+came\s+before|from\s+the\s+(?:beginning|start))\b",
        0.6, atlas=_SPE, owasp=("LLM07",),
    ),
    PatternRule(
        "SP-003", "Prompt echo via forced prefix", "prompt_extraction",
        r"\b(?:begin|start)\s+your\s+(?:reply|response|answer|output)\s+with\b[\s\S]{0,40}?\b(?:you\s+are|system|instructions|my\s+instructions)",
        0.5, atlas=_SPE, owasp=("LLM07",),
    ),
)


# --- Data loss prevention -------------------------------------------------

@dataclass(frozen=True)
class DlpRule:
    id: str
    title: str
    data_type: str
    pattern: str
    severity: str  # info|low|medium|high|critical
    flags: str = ""
    validator: str | None = None  # luhn | iban | ssn | entropy | none
    group: int = 0  # regex group holding the sensitive value
    min_entropy: float = 0.0
    redact: bool = True
    attack: tuple[str, ...] = ()

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "data_type": self.data_type,
            "pattern": self.pattern,
            "flags": self.flags,
            "severity": self.severity,
            "validator": self.validator,
            "group": self.group,
            "min_entropy": self.min_entropy,
        }


DLP_RULES: tuple[DlpRule, ...] = (
    # Cloud & SaaS credentials
    DlpRule("DLP-AWS-AKID", "AWS access key id", "secret.aws_access_key", r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b", "high", attack=("T1552",)),
    DlpRule("DLP-AWS-SECRET", "AWS secret access key", "secret.aws_secret_key", r"\baws.{0,20}?(?:secret|private).{0,20}?[\"'=:\s]{1,4}([A-Za-z0-9/+]{40})\b", "critical", flags="i", group=1, min_entropy=4.0, attack=("T1552",)),
    DlpRule("DLP-GCP-KEY", "Google API key", "secret.google_api_key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "high"),
    DlpRule("DLP-GCP-SA", "Google service account private key", "secret.gcp_service_account", r"\"type\"\s*:\s*\"service_account\"[\s\S]{0,400}?\"private_key\"", "critical"),
    DlpRule("DLP-AZURE-CONN", "Azure storage connection string", "secret.azure_storage", r"\bAccountKey=[A-Za-z0-9+/=]{60,}", "critical"),
    DlpRule("DLP-GH-TOKEN", "GitHub token", "secret.github_token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b", "high"),
    DlpRule("DLP-GITLAB", "GitLab token", "secret.gitlab_token", r"\bglpat-[A-Za-z0-9_\-]{20,}\b", "high"),
    DlpRule("DLP-SLACK-TOKEN", "Slack token", "secret.slack_token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b", "high"),
    DlpRule("DLP-SLACK-HOOK", "Slack webhook URL", "secret.slack_webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", "high"),
    DlpRule("DLP-STRIPE", "Stripe secret key", "secret.stripe_key", r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b", "critical"),
    DlpRule("DLP-ANTHROPIC", "Anthropic API key", "secret.anthropic_key", r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{60,}\b", "high"),
    DlpRule("DLP-OPENAI", "OpenAI API key", "secret.openai_key", r"\bsk-(?:proj-|svcacct-|admin-|None-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b|\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}\b", "high"),
    DlpRule("DLP-HF", "Hugging Face token", "secret.huggingface_token", r"\bhf_[A-Za-z0-9]{34,40}\b", "high"),
    DlpRule("DLP-NPM", "npm access token", "secret.npm_token", r"\bnpm_[A-Za-z0-9]{36}\b", "high"),
    DlpRule("DLP-PYPI", "PyPI upload token", "secret.pypi_token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b", "high"),
    DlpRule("DLP-SENDGRID", "SendGrid API key", "secret.sendgrid_key", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", "high"),
    DlpRule("DLP-TWILIO", "Twilio API key", "secret.twilio_key", r"\bSK[0-9a-fA-F]{32}\b", "medium"),
    DlpRule("DLP-PRIVKEY", "Private key", "secret.private_key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----", "critical", attack=("T1552",)),
    DlpRule("DLP-JWT", "JSON Web Token", "secret.jwt", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "medium"),
    DlpRule("DLP-CONNSTR", "Database URL with credentials", "secret.connection_string", r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver)://[^\s:/@]{1,64}:([^\s@/]{3,128})@[^\s/]+", "high", group=1),
    DlpRule("DLP-PASSWORD", "Hard-coded password or secret", "secret.password_assignment", r"\b(?:password|passwd|pwd|passphrase|secret|client_secret|api_?key|apikey|access_?token|auth_?token|private_?key)\b[\"']?\s*[:=]\s*[\"']?([^\s\"',;]{8,128})", "high", flags="i", group=1, validator="entropy", min_entropy=3.0),
    DlpRule("DLP-BASIC-AUTH", "Credentials in URL", "secret.url_credentials", r"\bhttps?://[^\s:/@]{1,64}:([^\s@/]{3,128})@[^\s/]+", "high", group=1),
    # Personal data
    DlpRule("DLP-EMAIL", "Email address", "pii.email", r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}\b", "low", redact=True),
    DlpRule("DLP-SSN", "US Social Security number", "pii.us_ssn", r"\b(\d{3})-(\d{2})-(\d{4})\b", "high", validator="ssn"),
    DlpRule("DLP-CC", "Payment card number", "pii.payment_card", r"\b(?:\d[ \-]?){12,18}\d\b", "high", validator="luhn"),
    DlpRule("DLP-IBAN", "IBAN bank account", "pii.iban", r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b", "high", validator="iban"),
    DlpRule("DLP-PHONE", "Phone number", "pii.phone", r"(?<![\w+])(?:\+?1[ .\-]?)?\(?[2-9]\d{2}\)?[ .\-]\d{3}[ .\-]\d{4}\b", "low"),
    DlpRule("DLP-IPV4-PRIV", "Internal IP address", "infra.private_ip", r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b", "info", redact=False),
    DlpRule("DLP-CLASSIFIED", "Classification marking", "corp.classification_marking", r"\b(?:strictly\s+confidential|internal\s+use\s+only|do\s+not\s+(?:distribute|forward)|attorney[- ]client\s+privileged|privileged\s+(?:and|&)\s+confidential|trade\s+secret|top\s+secret|restricted\s+data|NDA\s+protected|company\s+confidential)\b", "medium", flags="i", redact=False),
    DlpRule("DLP-CLASSIFIED-CAPS", "Classification banner", "corp.classification_marking", r"\b(?:CONFIDENTIAL|INTERNAL ONLY|PROPRIETARY|SECRET//[A-Z]+)\b", "medium", redact=False),
)
