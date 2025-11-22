import hashlib
from typing import Dict, List, Optional

from config import get_panel_password
from .storage_adapter import get_storage_adapter


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


async def _load_accounts() -> List[Dict[str, str]]:
    storage_adapter = await get_storage_adapter(namespace="accounts")
    accounts = await storage_adapter.get_config("accounts") or []
    return accounts


async def _save_accounts(accounts: List[Dict[str, str]]) -> None:
    storage_adapter = await get_storage_adapter(namespace="accounts")
    await storage_adapter.set_config("accounts", accounts)


async def ensure_default_account() -> List[Dict[str, str]]:
    accounts = await _load_accounts()
    if accounts:
        return accounts

    default_password = await get_panel_password()
    default_account = {
        "username": "admin",
        "password_hash": _hash_password(default_password),
        "is_admin": True,
    }
    await _save_accounts([default_account])
    return [default_account]


async def list_accounts(include_sensitive: bool = False) -> List[Dict[str, str]]:
    accounts = await ensure_default_account()
    if include_sensitive:
        return accounts

    safe_accounts: List[Dict[str, str]] = []
    for account in accounts:
        safe_accounts.append({"username": account.get("username"), "is_admin": account.get("is_admin", False)})
    return safe_accounts


async def upsert_account(username: str, password: str, is_admin: bool = False) -> None:
    accounts = await ensure_default_account()
    password_hash = _hash_password(password)

    updated = False
    for account in accounts:
        if account.get("username") == username:
            account["password_hash"] = password_hash
            account["is_admin"] = is_admin
            updated = True
            break

    if not updated:
        accounts.append({"username": username, "password_hash": password_hash, "is_admin": is_admin})

    await _save_accounts(accounts)


async def remove_account(username: str) -> None:
    accounts = await ensure_default_account()
    accounts = [account for account in accounts if account.get("username") != username]

    if not accounts:
        raise ValueError("至少需要保留一个账号")

    await _save_accounts(accounts)


def _find_account(username: str, accounts: List[Dict[str, str]]) -> Optional[Dict[str, str]]:
    for account in accounts:
        if account.get("username") == username:
            return account
    return None


async def authenticate(username: str, password: str) -> bool:
    accounts = await ensure_default_account()
    account = _find_account(username, accounts)
    if not account:
        return False

    return account.get("password_hash") == _hash_password(password)


async def is_admin(username: str) -> bool:
    accounts = await ensure_default_account()
    account = _find_account(username, accounts)
    return bool(account and account.get("is_admin", False))
