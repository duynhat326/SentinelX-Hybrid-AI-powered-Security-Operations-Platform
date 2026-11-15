import json

import pytest
from fastapi.testclient import TestClient

KEY = "k" * 32


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINELX_DATABASE_URL", f"sqlite+pysqlite:///{tmp_path}/t.db")
    monkeypatch.setenv("SENTINELX_API_KEY", KEY)
    from app.core import config
    from app.database import session

    config.get_settings.cache_clear()
    session._engine = session._factory = None
    from app.api.main import app

    with TestClient(app, headers={"X-API-Key": KEY}) as c:
        yield c


def ssh_fail(n: int, ip: str = "203.0.113.50") -> dict:
    line = f"2026-11-15T10:00:{n:02d}+00:00 web01 sshd[1201]: Failed password for invalid user admin from {ip} port {40220 + n} ssh2"
    return {"source": "linux_auth", "payload": line}


def sysmon_ps(cmd: str, t: str = "2026-11-15 10:05:00.000") -> dict:
    rec = {"EventID": 1, "UtcTime": t, "Computer": "win10-lab", "User": "LAB\\alice",
           "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
           "ParentImage": "C:\\Windows\\System32\\cmd.exe", "CommandLine": cmd}
    return {"source": "sysmon", "payload": json.dumps(rec)}
