"""Public demo input restrictions. No upload enabled by default."""
import os
from pathlib import Path

MAX_UPLOAD_BYTES = 5_000_000
SAFE_UPLOAD_ERROR = "Não foi possível ler o arquivo. Verifique o formato CSV/JSON e utilize apenas dados autorizados."

def uploads_enabled() -> bool:
    """Require private deployment mode plus opt-in; public demos stay disabled by default."""
    return (
        os.environ.get("CYBERSHIELD_DEPLOYMENT_MODE", "").strip().lower() == "private"
        and os.environ.get("CYBERSHIELD_ENABLE_UPLOADS", "").strip() == "1"
        and os.environ.get("CYBERSHIELD_PUBLIC_DEMO", "1").strip() == "0"
    )

def validate_upload(filename: str, size: int) -> str:
    """Validate metadata; callers must still parse file content defensively."""
    if not isinstance(filename, str) or not filename or "\x00" in filename:
        raise ValueError("Nome de arquivo inválido")
    suffix = Path(filename).suffix.lower()
    if suffix not in {".csv", ".json"}:
        raise ValueError("Formato permitido: CSV ou JSON")
    if not isinstance(size, int) or size < 0 or size > MAX_UPLOAD_BYTES:
        raise ValueError("O arquivo deve ter no máximo 5 MB")
    return suffix
