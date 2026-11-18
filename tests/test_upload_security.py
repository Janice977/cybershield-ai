import pytest
from src.upload_security import uploads_enabled, validate_upload, MAX_UPLOAD_BYTES

def test_upload_disabled_by_default(monkeypatch):
    monkeypatch.delenv("CYBERSHIELD_ENABLE_UPLOADS", raising=False)
    assert uploads_enabled() is False

def test_explicit_local_opt_in(monkeypatch):
    monkeypatch.setenv("CYBERSHIELD_ENABLE_UPLOADS", "1")
    assert uploads_enabled() is False
    monkeypatch.setenv("CYBERSHIELD_DEPLOYMENT_MODE", "private")
    assert uploads_enabled() is False
    monkeypatch.setenv("CYBERSHIELD_PUBLIC_DEMO", "0")
    assert uploads_enabled() is True
    monkeypatch.setenv("CYBERSHIELD_ENABLE_UPLOADS", "true")
    assert uploads_enabled() is False

@pytest.mark.parametrize("filename,size", [("arquivo.exe",100),("dados.csv",MAX_UPLOAD_BYTES+1),("",5),("bad\x00.json",1)])
def test_invalid_upload_rejected(filename,size):
    with pytest.raises(ValueError): validate_upload(filename,size)

def test_allow_expected_extensions():
    assert validate_upload("dados.csv", 10)==".csv"
    assert validate_upload("dados.JSON", 10)==".json"


def test_public_demo_cannot_enable_uploads(monkeypatch):
    monkeypatch.setenv("CYBERSHIELD_DEPLOYMENT_MODE", "private")
    monkeypatch.setenv("CYBERSHIELD_ENABLE_UPLOADS", "1")
    monkeypatch.setenv("CYBERSHIELD_PUBLIC_DEMO", "1")
    assert uploads_enabled() is False

def test_legacy_flag_alone_cannot_enable_uploads(monkeypatch):
    monkeypatch.setenv("CYBERSHIELD_ENABLE_UPLOADS", "1")
    monkeypatch.delenv("CYBERSHIELD_DEPLOYMENT_MODE", raising=False)
    monkeypatch.setenv("CYBERSHIELD_PUBLIC_DEMO", "0")
    assert uploads_enabled() is False
