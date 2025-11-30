import hashlib
import secrets
import string
import time
from typing import Dict, List, Optional

from config import get_admin_password, get_admin_username
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


API_KEY_LENGTH = 32
API_KEY_CHARS = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-"


def _ensure_unique_api_key(account: Dict[str, str], existing_keys: set[str]) -> bool:
    """Ensure the account has a unique API key. Returns True if updated."""

    current_key = account.get("api_key")
    if current_key and current_key not in existing_keys:
        existing_keys.add(current_key)
        return False

    for _ in range(20):
        candidate = "".join(secrets.choice(API_KEY_CHARS) for _ in range(API_KEY_LENGTH))
        if candidate not in existing_keys:
            account["api_key"] = candidate
            existing_keys.add(candidate)
            return True

    raise RuntimeError("无法生成唯一的调用密钥，请稍后重试")


async def ensure_default_account() -> List[Dict[str, str]]:
    accounts = await _load_accounts()

    existing_keys: set[str] = set()
    updated = False

    admin_username = await get_admin_username()
    admin_password = await get_admin_password()
    admin_password_hash = _hash_password(admin_password)

    # 如果已经存在账号，确保管理员账号被同步到最新配置
    if accounts:
        admin_found = False
        for account in accounts:
            if account.get("is_admin"):
                admin_found = True
                account.update(
                    {
                        "username": admin_username,
                        "password_hash": admin_password_hash,
                        "is_admin": True,
                        "disabled": False,
                    }
                )
                if _ensure_unique_api_key(account, existing_keys):
                    updated = True
            elif account.get("username") == admin_username:
                # 如果已存在同名的非管理员账号，将其升级为管理员
                account.update(
                    {
                        "is_admin": True,
                        "password_hash": admin_password_hash,
                        "disabled": False,
                    }
                )
                if _ensure_unique_api_key(account, existing_keys):
                    updated = True
                admin_found = True
            else:
                if _ensure_unique_api_key(account, existing_keys):
                    updated = True
        if not admin_found:
            new_admin = {
                "username": admin_username,
                "password_hash": admin_password_hash,
                "is_admin": True,
                "disabled": False,
                "created_at": time.time(),
                "api_key": "",
            }
            _ensure_unique_api_key(new_admin, existing_keys)
            accounts.append(new_admin)
            updated = True

        if updated:
            await _save_accounts(accounts)
        return accounts

    default_account = {
        "username": admin_username,
        "password_hash": admin_password_hash,
        "is_admin": True,
        "disabled": False,
        "created_at": time.time(),
        "api_key": "",
    }
    _ensure_unique_api_key(default_account, existing_keys)
    await _save_accounts([default_account])
    return [default_account]


async def list_accounts(include_sensitive: bool = False) -> List[Dict[str, str]]:
    accounts = await ensure_default_account()
    if include_sensitive:
        return accounts

    safe_accounts: List[Dict[str, str]] = []
    for account in accounts:
        safe_accounts.append(
            {
                "username": account.get("username"),
                "is_admin": account.get("is_admin", False),
                "disabled": account.get("disabled", False),
                "last_login": account.get("last_login"),
                "last_call": account.get("last_call"),
            }
        )
    return safe_accounts


async def upsert_account(
    username: str, password: str, is_admin: bool = False, disabled: bool = False
) -> None:
    accounts = await ensure_default_account()
    password_hash = _hash_password(password)

    updated = False
    existing_keys = {account.get("api_key") for account in accounts if account.get("api_key")}

    for account in accounts:
        if account.get("username") == username:
            account.update(
                {
                    "password_hash": password_hash,
                    "is_admin": is_admin,
                    "disabled": disabled,
                }
            )
            _ensure_unique_api_key(account, existing_keys)
            updated = True
            break

    if not updated:
        new_account = {
            "username": username,
            "password_hash": password_hash,
            "is_admin": is_admin,
            "disabled": disabled,
            "created_at": time.time(),
        }
        _ensure_unique_api_key(new_account, existing_keys)
        accounts.append(new_account)

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


async def authenticate(username: str, password: str) -> Dict[str, bool | str]:
    accounts = await ensure_default_account()
    account = _find_account(username, accounts)

    if not account:
        # 自主注册：账号不存在时创建新账号
        await upsert_account(username, password, is_admin=False, disabled=False)
        return {"success": True, "created": True}

    if account.get("disabled"):
        return {"success": False, "reason": "disabled"}

    if account.get("password_hash") == _hash_password(password):
        return {"success": True, "created": False}

    return {"success": False, "reason": "password_mismatch"}


async def is_admin(username: str) -> bool:
    accounts = await ensure_default_account()
    account = _find_account(username, accounts)
    return bool(account and account.get("is_admin", False))


async def is_disabled(username: str) -> bool:
    accounts = await ensure_default_account()
    account = _find_account(username, accounts)
    return bool(account and account.get("disabled", False))


async def set_disabled(username: str, disabled: bool) -> None:
    accounts = await ensure_default_account()
    for account in accounts:
        if account.get("username") == username:
            account["disabled"] = disabled
    await _save_accounts(accounts)


async def get_account(username: str) -> Optional[Dict[str, str]]:
    accounts = await ensure_default_account()
    return _find_account(username, accounts)


async def update_last_login(username: str) -> None:
    if not username:
        return
    accounts = await ensure_default_account()
    for account in accounts:
        if account.get("username") == username:
            account["last_login"] = time.time()
            break
    await _save_accounts(accounts)


async def update_last_call(username: str) -> None:
    if not username:
        return
    accounts = await ensure_default_account()
    for account in accounts:
        if account.get("username") == username:
            account["last_call"] = time.time()
            break
    await _save_accounts(accounts)


async def refresh_api_key(username: str) -> str:
    accounts = await ensure_default_account()
    existing_keys = {account.get("api_key") for account in accounts if account.get("api_key")}
    for account in accounts:
        if account.get("username") == username:
            _ensure_unique_api_key(account, existing_keys)
            await _save_accounts(accounts)
            return account.get("api_key", "")
    raise ValueError("用户不存在")


async def get_account_by_api_key(api_key: str) -> Optional[Dict[str, str]]:
    if not api_key:
        return None

    accounts = await ensure_default_account()
    for account in accounts:
        if account.get("api_key") == api_key:
            if account.get("disabled"):
                return None
            return account
    return None


async def get_account_api_key(username: str) -> Optional[str]:
    accounts = await ensure_default_account()
    account = _find_account(username, accounts)
    return account.get("api_key") if account else None
