import json
from pathlib import Path

import pytest

from runner import public_config


def test_template_has_no_deployment_secrets():
    import yaml
    data = yaml.safe_load((public_config.ROOT / 'configs/scan.example.yaml').read_text(encoding='utf8'))
    assert data['web']['base_url'] == ''
    assert data['api']['openapi_secret'] == ''
    assert data['hosts']['ssh_pass'] == ''
    assert not data['scan']['allow_write_chain']


def test_local_hosts_and_target_are_read_from_config(tmp_path, monkeypatch):
    config = tmp_path / 'scan.yaml'
    config.write_text('web: {base_url: "https://demo.example.test:28443"}\nhosts: {app_ip: "192.0.2.20", ssh_pass: "${DEMO_PASS}"}\n', encoding='utf8')
    monkeypatch.setenv('GATE_SCAN_CONFIG', str(config))
    monkeypatch.delenv('GATE_BASE_URL', raising=False)
    monkeypatch.setenv('DEMO_PASS', 'synthetic-password')
    assert public_config.target() == 'https://demo.example.test:28443'
    assert public_config.env('SEC_SSH_HOST') == '192.0.2.20'
    assert public_config.env('SEC_SSH_PASSWORD') == 'synthetic-password'


def test_environment_overrides_local_config(monkeypatch):
    monkeypatch.setenv('SEC_SSH_HOST', '192.0.2.30')
    assert public_config.env('SEC_SSH_HOST') == '192.0.2.30'


def test_shell_requires_missing_credential(monkeypatch):
    monkeypatch.setenv('GATE_SCAN_CONFIG', 'not-present-publication-test.yaml')
    monkeypatch.delenv('SEC_SSH_PASSWORD', raising=False)
    with pytest.raises(ValueError, match='SEC_SSH_PASSWORD'):
        public_config.shell('SEC_SSH_PASSWORD')


def test_init_preserves_existing_configuration(tmp_path):
    import tools.init_local as init
    (tmp_path / 'configs').mkdir()
    (tmp_path / 'configs/scan.example.yaml').write_text('env: {name: template}', encoding='utf8')
    init.main(tmp_path)
    local = tmp_path / 'configs/scan.local.yaml'
    assert local.read_text(encoding='utf8') == 'env: {name: template}'
    local.write_text('env: {name: custom}', encoding='utf8')
    init.main(tmp_path)
    assert local.read_text(encoding='utf8') == 'env: {name: custom}'
    assert (tmp_path / 'evidence/tokens').is_dir()


def test_inventory_omits_captured_credentials():
    data = json.loads((public_config.ROOT / 'knowledge/endpoints.json').read_text(encoding='utf8'))
    assert data['endpoints']
    assert all('sample_headers' not in e and 'sample_body' not in e for e in data['endpoints'])
