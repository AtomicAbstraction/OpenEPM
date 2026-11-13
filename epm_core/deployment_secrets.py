"""Small strict helpers for service-owned secret-file configuration."""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path


def configured_text(environment: Mapping[str, str], direct_name: str,
                    file_name: str, *, maximum: int = 8192) -> str:
    """Resolve one direct development value or one production secret file.

    Production Compose uses Docker secret files. Local disposable development
    profiles may use a direct environment value. Ambiguous dual configuration
    fails closed rather than silently choosing one authority.
    """
    if (not isinstance(environment, Mapping)
            or not isinstance(direct_name, str) or not direct_name
            or not isinstance(file_name, str) or not file_name
            or type(maximum) is not int or maximum < 1):
        raise ValueError("DEPLOYMENT_SECRET_CONFIGURATION_INVALID")
    direct, path_value = environment.get(direct_name), environment.get(file_name)
    if direct and path_value:
        raise ValueError("DEPLOYMENT_SECRET_CONFIGURATION_AMBIGUOUS")
    if direct:
        value = direct
    elif path_value:
        path = Path(path_value)
        try:
            if not path.is_file() or path.is_symlink():
                raise ValueError
            value = path.read_text("utf-8").strip()
        except (OSError, UnicodeError, ValueError) as error:
            raise ValueError("DEPLOYMENT_SECRET_UNAVAILABLE") from error
    else:
        raise ValueError("DEPLOYMENT_SECRET_NOT_CONFIGURED")
    if (not isinstance(value, str) or not value or "\0" in value
            or len(value.encode("utf-8")) > maximum):
        raise ValueError("DEPLOYMENT_SECRET_INVALID")
    return value


def configured_hex_bytes(environment: Mapping[str, str], direct_name: str,
                         file_name: str, *, minimum: int = 32) -> bytes:
    """Resolve one hexadecimal secret from a direct value or a secret file.

    The deployment contract uses hexadecimal because the same values are
    accepted by the development Compose profiles.  The length check is on the
    decoded bytes, not the textual representation.
    """
    if type(minimum) is not int or minimum < 1:
        raise ValueError("DEPLOYMENT_SECRET_CONFIGURATION_INVALID")
    value = configured_text(environment, direct_name, file_name)
    try:
        secret = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError("DEPLOYMENT_SECRET_HEX_INVALID") from error
    if len(secret) < minimum:
        raise ValueError("DEPLOYMENT_SECRET_HEX_INVALID")
    return secret
