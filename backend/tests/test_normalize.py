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
