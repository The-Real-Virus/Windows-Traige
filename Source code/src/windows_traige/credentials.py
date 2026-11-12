"""Optional Windows Credential Manager storage bound to the current user."""

import ctypes
import os
import re
from ctypes import wintypes

from .assistant import HOSTS, KEY_ENV
from .common import Invalid, safe_path


class Credential(ctypes.Structure):
    _fields_ = [
        ("flags", wintypes.DWORD), ("type", wintypes.DWORD), ("target", wintypes.LPWSTR),
        ("comment", wintypes.LPWSTR), ("written", wintypes.FILETIME), ("length", wintypes.DWORD),
        ("blob", ctypes.POINTER(ctypes.c_ubyte)), ("persist", wintypes.DWORD),
        ("attribute_count", wintypes.DWORD), ("attributes", ctypes.c_void_p),
        ("alias", wintypes.LPWSTR), ("username", wintypes.LPWSTR),
    ]


def api(provider):
    if os.name != "nt" or provider not in HOSTS:
        raise Invalid("Credential Manager is unavailable")
    return ctypes.WinDLL("advapi32", use_last_error=True), f"Windows Traige/1/{provider}"


def from_file(provider, filename):
    path = safe_path(filename)
    if not path.is_file():
        raise Invalid("Choose a local text file containing one API key")
    with path.open("rb") as stream:
        raw = stream.read(4097)
    if len(raw) > 4096:
        raise Invalid("The API key file is too large")
    try:
        value = raw.decode("utf-8-sig").strip()
    except UnicodeError:
        raise Invalid("Save the API key file as UTF-8 text") from None
    if provider == "gemini":
        matches = re.findall(r"AIza[A-Za-z0-9_-]{20,}", value)
        if len(matches) == 1:
            return matches[0]
    if value.startswith(KEY_ENV[provider] + "="):
        value = value.partition("=")[2].strip().strip("\"'")
    if not re.fullmatch(r"[!-~]{8,512}", value):
        raise Invalid("The file must contain a single API key for the selected provider")
    return value


def save(provider, key):
    native, target = api(provider)
    raw = key.encode("utf-8")
    if not 1 <= len(raw) <= 512:
        raise Invalid("Supply a valid credential before saving")
    data = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
    item = Credential(type=1, target=target, length=len(data), blob=data, persist=2, username=provider)
    native.CredWriteW.argtypes = (ctypes.POINTER(Credential), wintypes.DWORD)
    native.CredWriteW.restype = wintypes.BOOL
    try:
        if not native.CredWriteW(ctypes.byref(item), 0):
            raise Invalid("Windows could not save the provider credential")
    finally:
        ctypes.memset(data, 0, len(data))


def load(provider):
    native, target = api(provider)
    pointer = ctypes.POINTER(Credential)()
    native.CredReadW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                 ctypes.POINTER(ctypes.POINTER(Credential)))
    native.CredReadW.restype = wintypes.BOOL
    native.CredFree.argtypes = (ctypes.c_void_p,)
    native.CredFree.restype = None
    if not native.CredReadW(target, 1, 0, ctypes.byref(pointer)):
        raise Invalid("Windows could not read a saved credential for this provider")
    try:
        item = pointer.contents
        if not 1 <= item.length <= 512:
            raise Invalid("Invalid saved provider credential")
        return ctypes.string_at(item.blob, item.length).decode("utf-8")
    finally:
        native.CredFree(pointer)


def delete(provider):
    native, target = api(provider)
    native.CredDeleteW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD)
    native.CredDeleteW.restype = wintypes.BOOL
    if not native.CredDeleteW(target, 1, 0) and ctypes.get_last_error() != 1168:
        raise Invalid("Windows could not remove the saved provider credential")
