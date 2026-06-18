from __future__ import annotations

from typing import Any, Optional, Tuple

from agno.utils.log import log_debug, log_warning


def load_token_from_db(
    db: Any,
    user_id: Optional[str],
    encryption_key: Optional[str],
) -> Tuple[Optional[dict], Any]:
    """Load Google OAuth token from DB and build Credentials.

    Returns:
        (row, creds): row dict for scope checking, Credentials object for use.
        (None, None): if not found or decryption/parse fails.
    """
    from google.oauth2.credentials import Credentials

    from agno.utils.encryption import decrypt_dict, is_encrypted

    try:
        row = db.get_auth_token("google", user_id, "google")
    except NotImplementedError:
        log_warning("Database does not support auth token storage")
        return None, None
    except Exception as e:
        log_debug(f"DB lookup failed: {e}")
        return None, None

    if not row:
        return None, None

    token_data = row.get("token_data")
    if not token_data:
        return None, None

    try:
        if is_encrypted(token_data):
            token_data = decrypt_dict(token_data, key=encryption_key)
        scopes = row.get("granted_scopes") or []
        creds = Credentials.from_authorized_user_info(token_data, scopes)
        return row, creds
    except (ValueError, KeyError, ImportError):
        return None, None


def save_token_to_db(
    db: Any,
    creds: Any,
    user_id: Optional[str],
    granted_scopes: list[str],
    encryption_key: Optional[str],
) -> bool:
    """Save Google OAuth credentials to DB."""
    from agno.utils.encryption import encrypt_dict

    token_data = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
    }

    if encryption_key:
        token_data = encrypt_dict(token_data, key=encryption_key)
    else:
        log_warning(
            "Saving Google token without encryption. "
            "Set AGNO_ENCRYPTION_KEY or auth.token_encryption_key for production use."
        )

    try:
        db.upsert_auth_token(
            {
                "provider": "google",
                "user_id": user_id,
                "service": "google",
                "token_data": token_data,
                "granted_scopes": granted_scopes,
            }
        )
        return True
    except Exception as e:
        log_debug(f"Failed to save credentials to DB: {e}")
        return False
