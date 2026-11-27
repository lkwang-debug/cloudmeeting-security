"""Keep publication tests isolated from real deployment configuration."""
import socket

import pytest


@pytest.fixture(autouse=True)
def isolate_environment(tmp_path, monkeypatch):
    monkeypatch.setenv('GATE_SCAN_CONFIG', str(tmp_path / 'no-real-environment.yaml'))
    monkeypatch.setenv('GATE_BASE_URL', 'http://127.0.0.1:1')
    monkeypatch.setenv('NO_PROXY', '*')
    monkeypatch.setenv('GATE_EVIDENCE_DIR', str(tmp_path / 'evidence'))
    # Command construction tests mock SSH; this documentation address is never contacted.
    monkeypatch.setenv('SEC_DB_HOST', '192.0.2.20')
    monkeypatch.setenv('SEC_REDIS_PASSWORD', 'synthetic-redis-password')
    original = socket.socket.connect

    def local_only(sock, address):
        if isinstance(address, tuple) and address[0] not in ('127.0.0.1', 'localhost', '::1'):
            raise OSError('Unit tests allow loopback connections only')
        return original(sock, address)

    monkeypatch.setattr(socket.socket, 'connect', local_only)
