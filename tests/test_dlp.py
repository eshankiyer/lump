from lump.engine.dlp import (
    CustomPattern,
    DlpConfig,
    DlpDetector,
    card_valid,
    edm_hash,
    fingerprint_shingles,
    iban_valid,
    redact,
)
from lump.engine.types import Severity


def ids(findings):
    return {f.rule_id for f in findings}


def test_aws_key_and_github_token():
    d = DlpDetector()
    f = d.detect("key AKIAIOSFODNN7EXAMPLE token ghp_" + "a" * 36)
    assert "DLP-AWS-AKID" in ids(f)
    assert "DLP-GH-TOKEN" in ids(f)


def test_private_key_and_jwt():
    d = DlpDetector()
    f = d.detect("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----")
    assert "DLP-PRIVKEY" in ids(f)


def test_credit_card_luhn_validation():
    assert card_valid("4111 1111 1111 1111")
    assert not card_valid("4111 1111 1111 1112")
    d = DlpDetector()
    assert "DLP-CC" in ids(d.detect("card 4111 1111 1111 1111"))
    assert "DLP-CC" not in ids(d.detect("order number 1234 5678 9012 3456 7"))  # fails luhn/prefix


def test_iban_validation():
    assert iban_valid("GB82 WEST 1234 5698 7654 32")
    assert not iban_valid("GB00 WEST 1234 5698 7654 32")


def test_password_requires_entropy():
    d = DlpDetector()
    assert "DLP-PASSWORD" not in ids(d.detect('password = "changeme"'))
    assert "DLP-PASSWORD" not in ids(d.detect('password = os.environ["PW"]'))
    assert "DLP-PASSWORD" in ids(d.detect('password = "G7!xQ29zLp0w"'))


def test_redaction_masks_values():
    d = DlpDetector()
    text = "my secret key is AKIAIOSFODNN7EXAMPLE ok"
    findings = d.detect(text)
    out = redact(text, findings)
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "[REDACTED:" in out


def test_custom_pattern_and_keyword():
    cfg = DlpConfig(
        keywords=["Project Bluebird"],
        custom_patterns=[CustomPattern("EMP-ID", "Employee id", r"\bEMP-\d{6}\b", Severity.MEDIUM)],
    )
    d = DlpDetector(cfg)
    f = d.detect("ticket for EMP-123456 on Project Bluebird")
    assert "EMP-ID" in ids(f)
    assert "DLP-KEYWORD" in ids(f)


def test_exact_data_match():
    salt = "s"
    cfg = DlpConfig(edm_salt=salt, edm_hashes={edm_hash("ACME-CUST-0001", salt)})
    d = DlpDetector(cfg)
    assert "DLP-EDM" in ids(d.detect("the account is ACME-CUST-0001 in the system"))
    assert "DLP-EDM" not in ids(d.detect("the account is ACME-CUST-9999 in the system"))


def test_document_fingerprint():
    protected = "the quarterly revenue target for the northern region exceeds all prior internal projections by a wide margin this year"
    cfg = DlpConfig(fingerprints={"strategy": fingerprint_shingles(protected)}, fingerprint_min_shingles=3, fingerprint_threshold=0.1)
    d = DlpDetector(cfg)
    leaked = "As noted, the quarterly revenue target for the northern region exceeds all prior internal projections by a wide margin this year, per the deck."
    assert "DLP-FINGERPRINT" in ids(d.detect(leaked))


def test_source_code_detection():
    d = DlpDetector()
    code = "\n".join(["import os", "def run():", "    return os.getcwd()", "class A:", "    pass", "for i in range(10):", "    print(i)"])
    assert "DLP-SOURCE" in ids(d.detect(code))
