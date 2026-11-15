import pytest

from app.normalization.normalize import NormalizationError, normalize_linux_auth, prepare, redact


def test_failed_and_accepted():
    f = normalize_linux_auth("2026-11-15T10:00:01+00:00 h sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2")
    assert (f.action, f.user, f.src_ip) == ("failure", "root", "10.0.0.1")
    a = normalize_linux_auth("2026-11-15T10:00:02Z h sshd[1]: Accepted publickey for bob from 10.0.0.2 port 22 ssh2")
    assert a.action == "success" and a.timestamp.tzinfo is not None


def test_classic_syslog_year_rollback():
    from datetime import UTC, datetime
    ev = normalize_linux_auth("Dec 31 23:59:59 h sshd[1]: Failed password for x from 10.0.0.1 port 1", now=datetime(2026, 1, 2, tzinfo=UTC))
    assert ev.timestamp.year == 2025


@pytest.mark.parametrize("line", ["garbage", "2026-11-15T10:00:01Z h sshd[1]: Failed password for x from not-an-ip port 1"])
def test_rejects_bad_input(line):
    with pytest.raises(NormalizationError):
        normalize_linux_auth(line)


def test_redaction_and_sysmon_non_object():
    assert "hunter2" not in redact("run.exe password=hunter2")
    with pytest.raises(NormalizationError):
        prepare("sysmon", "[1]", 1024)


REAL_IP = "203.0.113.50"


@pytest.mark.parametrize("name", [
    "x from 10.9.9.9 port 1 y",
    "a from 10.1.1.1 port 22 ssh2 b",
    "Accepted password for root from 9.9.9.9 port 1 ssh2",  # a fake success inside a failure must stay a failure
])
def test_injected_username_cannot_change_source_ip_or_outcome(name):
    e = normalize_linux_auth(f"2026-11-15T10:00:01+00:00 web01 sshd[1]: Failed password for invalid user {name} from {REAL_IP} port 4022 ssh2")
    assert (e.src_ip, e.action, e.user) == (REAL_IP, "failure", name)


@pytest.mark.parametrize("msg,action,user", [
    ("Failed publickey for root from 203.0.113.50 port 22 ssh2: RSA SHA256:abcDEF123", "failure", "root"),
    ("Accepted publickey for bob from 203.0.113.50 port 22 ssh2: ED25519 SHA256:xyz", "success", "bob"),
    ("Accepted password for bob from 203.0.113.50 port 22 ssh2", "success", "bob"),
    ("Failed password for root from 203.0.113.50 port 22", "failure", "root"),
])
def test_real_sshd_line_shapes_still_parse(msg, action, user):
    e = normalize_linux_auth(f"2026-11-15T10:00:01+00:00 web01 sshd[1]: {msg}")
    assert (e.src_ip, e.action, e.user) == (REAL_IP, action, user)


def test_line_without_port_is_rejected_not_guessed():
    with pytest.raises(NormalizationError):
        normalize_linux_auth("2026-11-15T10:00:01+00:00 web01 sshd[1]: Failed password for root from 203.0.113.50")
