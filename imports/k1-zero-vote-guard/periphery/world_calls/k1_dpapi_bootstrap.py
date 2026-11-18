
"""K1 Windows DPAPI CurrentUser key loader. No key creation."""

import base64
import ctypes
import os
import stat
from ctypes import wintypes
from pathlib import Path


_ENTROPY = b"OBSIDIA_KX108_KERNEL_HMAC_DPAPI_V1"


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _make_blob(value):
    buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
    blob = _DataBlob(
        len(value),
        ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
    )
    return blob, buffer


def _check_path(path):
    if (
        path.is_symlink()
        or getattr(path, "is_junction", lambda: False)()
    ):
        raise PermissionError("K1_DPAPI_REDIRECTED_PATH")

    info = path.lstat()

    if getattr(info, "st_file_attributes", 0) & getattr(
        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
    ):
        raise PermissionError("K1_DPAPI_REPARSE_POINT")


def load_k1_dpapi_key_text():
    """
    Return the base64 text previously supplied to get_kernel_key.
    Return None only if no DPAPI file was provisioned.
    A present but invalid file must fail closed.
    """
    if os.name != "nt":
        return None

    local = os.environ.get("LOCALAPPDATA")

    if not local:
        return None

    directory = Path(local) / "Obsidia" / "KX108"
    path = directory / "kernel-hmac-v1.dpapi"

    if not os.path.lexists(str(directory)):
        return None

    _check_path(directory)

    if not directory.is_dir():
        raise PermissionError("K1_DPAPI_DIRECTORY_INVALID")

    if not os.path.lexists(str(path)):
        return None

    _check_path(path)

    if not path.is_file():
        raise PermissionError("K1_DPAPI_FILE_INVALID")

    if path.stat().st_size > 1048576:
        raise PermissionError("K1_DPAPI_FILE_OVERSIZED")

    encrypted = path.read_bytes()

    if not encrypted:
        raise PermissionError("K1_DPAPI_FILE_EMPTY")

    input_blob, input_buffer = _make_blob(encrypted)
    entropy_blob, entropy_buffer = _make_blob(_ENTROPY)
    output_blob = _DataBlob()

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    unprotect = crypt32.CryptUnprotectData
    unprotect.argtypes = [
        ctypes.POINTER(_DataBlob),
        ctypes.POINTER(ctypes.c_wchar_p),
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    unprotect.restype = wintypes.BOOL

    release = kernel32.LocalFree
    release.argtypes = [ctypes.c_void_p]
    release.restype = ctypes.c_void_p

    success = unprotect(
        ctypes.byref(input_blob),
        None,
        ctypes.byref(entropy_blob),
        None,
        None,
        0x1,  # CRYPTPROTECT_UI_FORBIDDEN
        ctypes.byref(output_blob),
    )

    if not success:
        raise PermissionError("K1_DPAPI_UNPROTECT_FAILED")

    try:
        if output_blob.cbData != 32 or not output_blob.pbData:
            raise PermissionError("K1_DPAPI_KEY_LENGTH_INVALID")

        # Preserve the current canonical key representation:
        # base64 text encoded as UTF-8 by get_kernel_key().
        raw = ctypes.string_at(output_blob.pbData, 32)
        return base64.b64encode(raw).decode("ascii")
    finally:
        if output_blob.pbData:
            ctypes.memset(
                output_blob.pbData, 0, output_blob.cbData
            )
            release(
                ctypes.cast(output_blob.pbData, ctypes.c_void_p)
            )
