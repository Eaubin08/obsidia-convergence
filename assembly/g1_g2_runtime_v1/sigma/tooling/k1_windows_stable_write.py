"""K1 Windows-only pinned, non-shareable writable file handle.

No authorization is issued here. Caller supplies an already verified
target preimage attestation, a verified KX108 action and its payload.
"""
from __future__ import annotations

import hashlib
import os
import stat
from contextlib import contextmanager
from pathlib import Path


class StableHandleRefused(PermissionError):
    """Refuse ACT before changing physical bytes; keep authenticated WAL."""


@contextmanager
def pin_verified_windows_postimage(
    target, worktree, expected_digest, expected_identity=None,
):
    """Keep the *verified* path and bytes pinned through publication.

    An after-the-fact hash check without this sharing fence leaves a
    check/use race. The pinned target denies both WRITE and DELETE sharing;
    ancestors are pinned against rename. Callers must keep this context open
    until COMMITTED/RECOVERED and journal cleanup are complete.
    """
    if os.name != "nt":
        raise StableHandleRefused("K1_PINNED_FINALITY_WINDOWS_ONLY")
    if not isinstance(expected_digest, str) or len(expected_digest) != 64:
        raise StableHandleRefused("K1_PINNED_POSTIMAGE_DIGEST_INVALID")

    import ctypes
    import msvcrt
    from ctypes import wintypes

    root = Path(worktree).resolve(strict=True)
    target = Path(target)
    try:
        relative = target.resolve(strict=True).relative_to(root)
        if not relative.parts or relative.parts[0] in (".git", ".obsidia_wal"):
            raise StableHandleRefused("K1_PINNED_POSTIMAGE_PATH_PROTECTED")
    except StableHandleRefused:
        raise
    except Exception as exc:
        raise StableHandleRefused("K1_PINNED_POSTIMAGE_PATH_INVALID") from exc

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create = k32.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    close = k32.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL

    class Info(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    get_info = k32.GetFileInformationByHandle
    get_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(Info)]
    get_info.restype = wintypes.BOOL

    FILE_READ_ATTRIBUTES = 0x80
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x1
    FILE_SHARE_WRITE = 0x2
    OPEN_EXISTING = 3
    BACKUP_SEMANTICS = 0x02000000
    OPEN_REPARSE_POINT = 0x00200000
    REPARSE_ATTRIBUTE = 0x400
    DIRECTORY_ATTRIBUTE = 0x10
    invalid = ctypes.c_void_p(-1).value
    parents = []
    raw = None
    stream = None

    try:
        for depth in range(len(relative.parts)):
            directory = root.joinpath(*relative.parts[:depth])
            handle = create(
                str(directory), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None, OPEN_EXISTING,
                BACKUP_SEMANTICS | OPEN_REPARSE_POINT, None,
            )
            if handle in (None, invalid):
                raise StableHandleRefused("K1_FINALITY_PARENT_PIN_REFUSED")
            parents.append(handle)
            info = Info()
            if (not get_info(handle, ctypes.byref(info))
                    or not info.dwFileAttributes & DIRECTORY_ATTRIBUTE
                    or info.dwFileAttributes & REPARSE_ATTRIBUTE):
                raise StableHandleRefused("K1_FINALITY_PARENT_IDENTITY_INVALID")

        raw = create(
            str(target), GENERIC_READ, FILE_SHARE_READ,
            None, OPEN_EXISTING, OPEN_REPARSE_POINT, None,
        )
        if raw in (None, invalid):
            raise StableHandleRefused("K1_FINALITY_TARGET_PIN_REFUSED")

        info = Info()
        if not get_info(raw, ctypes.byref(info)):
            raise StableHandleRefused("K1_FINALITY_FILE_IDENTITY_UNAVAILABLE")
        if (info.dwFileAttributes & (REPARSE_ATTRIBUTE | DIRECTORY_ATTRIBUTE)
                or info.nNumberOfLinks != 1):
            raise StableHandleRefused("K1_FINALITY_REDIRECT_OR_HARDLINK")

        # Compare the current canonical path to the native pinned file.
        path_handle = create(
            str(target), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None, OPEN_EXISTING, OPEN_REPARSE_POINT, None,
        )
        if path_handle in (None, invalid):
            raise StableHandleRefused("K1_FINALITY_PATH_HANDLE_REFUSED")
        try:
            path_info = Info()
            if not get_info(path_handle, ctypes.byref(path_info)):
                raise StableHandleRefused("K1_FINALITY_PATH_IDENTITY_UNAVAILABLE")
            pinned_id = (info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow)
            path_id = (
                path_info.dwVolumeSerialNumber,
                path_info.nFileIndexHigh, path_info.nFileIndexLow,
            )
            if pinned_id != path_id:
                raise StableHandleRefused("K1_FINALITY_PATH_IDENTITY_MISMATCH")
        finally:
            close(path_handle)

        if expected_identity is not None:
            current = os.lstat(target)
            if (current.st_dev, current.st_ino) != tuple(expected_identity):
                raise StableHandleRefused("K1_FINALITY_FILE_IDENTITY_CHANGED")

        fd = msvcrt.open_osfhandle(
            int(raw), os.O_RDONLY | getattr(os, "O_BINARY", 0)
        )
        raw = None
        stream = os.fdopen(fd, "rb", buffering=0)
        if hashlib.sha256(stream.read()).hexdigest() != expected_digest:
            raise StableHandleRefused("K1_PINNED_POSTIMAGE_MISMATCH")
        yield
    finally:
        if stream is not None:
            stream.close()
        if raw not in (None, invalid):
            close(raw)
        for parent in reversed(parents):
            close(parent)


def write_existing_windows_target(target, payload, expected, worktree, attest):
    """Pin parents and target, then revalidate/write/fsync using ONE handle.

    Windows CreateFileW sharing prevents new writer/delete opens on the
    pinned target; parent handles prevent path-directory renames.
    A last-moment replacement must match the same approved file identity.
    """
    if os.name != "nt":
        raise StableHandleRefused("K1_STABLE_HANDLE_WINDOWS_ONLY")
    if not isinstance(payload, bytes) or not isinstance(expected, tuple):
        raise StableHandleRefused("K1_STABLE_HANDLE_ARGUMENT_INVALID")

    import ctypes
    import msvcrt
    from ctypes import wintypes

    root = Path(worktree).resolve(strict=True)
    target = Path(target)
    try:
        relative = target.resolve(strict=True).relative_to(root)
        if relative.parts[0] in (".git", ".obsidia_wal"):
            raise StableHandleRefused("K1_STABLE_HANDLE_PROTECTED_PATH")
        if attest(root, relative.as_posix()) != expected:
            raise StableHandleRefused("K1_STABLE_HANDLE_PREOPEN_DRIFT")
    except StableHandleRefused:
        raise
    except Exception as exc:
        raise StableHandleRefused("K1_STABLE_HANDLE_TARGET_INVALID") from exc

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create = k32.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    close = k32.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL

    class Info(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    get_info = k32.GetFileInformationByHandle
    get_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(Info)]
    get_info.restype = wintypes.BOOL

    FILE_SHARE_READ = 0x1
    FILE_SHARE_WRITE = 0x2
    FILE_READ_ATTRIBUTES = 0x80
    GENERIC_READ_WRITE = 0xC0000000
    OPEN_EXISTING = 3
    BACKUP_SEMANTICS = 0x02000000
    OPEN_REPARSE_POINT = 0x00200000
    REPARSE_ATTRIBUTE = 0x400
    DIRECTORY_ATTRIBUTE = 0x10
    invalid = ctypes.c_void_p(-1).value
    parents = []
    raw_file = None
    wrote = False

    try:
        # Keep every path-bearing ancestor pinned with DELETE sharing denied.
        for depth in range(len(relative.parts)):
            directory = root.joinpath(*relative.parts[:depth])
            handle = create(
                str(directory),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None, OPEN_EXISTING,
                BACKUP_SEMANTICS | OPEN_REPARSE_POINT, None,
            )
            if handle in (None, invalid):
                raise StableHandleRefused("K1_PARENT_DIRECTORY_PIN_REFUSED")
            parents.append(handle)
            metadata = Info()
            if not get_info(handle, ctypes.byref(metadata)):
                raise StableHandleRefused("K1_PARENT_IDENTITY_UNAVAILABLE")
            if not metadata.dwFileAttributes & DIRECTORY_ATTRIBUTE:
                raise StableHandleRefused("K1_PARENT_NOT_DIRECTORY")
            if metadata.dwFileAttributes & REPARSE_ATTRIBUTE:
                raise StableHandleRefused("K1_PARENT_REPARSE_REFUSED")

        raw_file = create(
            str(target),
            GENERIC_READ_WRITE,
            FILE_SHARE_READ,  # deny external write and delete opens
            None, OPEN_EXISTING, OPEN_REPARSE_POINT, None,
        )
        if raw_file in (None, invalid):
            raise StableHandleRefused("K1_TARGET_EXCLUSIVE_OPEN_REFUSED")

        metadata = Info()
        if not get_info(raw_file, ctypes.byref(metadata)):
            raise StableHandleRefused("K1_FILE_IDENTITY_UNAVAILABLE")
        if (metadata.dwFileAttributes & (REPARSE_ATTRIBUTE | DIRECTORY_ATTRIBUTE)
                or metadata.nNumberOfLinks != 1):
            raise StableHandleRefused("K1_FILE_REDIRECT_OR_HARDLINK_REFUSED")

        # K1_NATIVE_IDENTITY_DUAL_HANDLE_V1
        # Compare volume serial and file index from TWO native Win32 handles.
        # The first is the pinned writable object; the second is opened by
        # the canonical target path while the first denies delete/rename.
        # Avoid comparing os.lstat and os.fstat timestamps/inode encodings.
        path_handle = create(
            str(target),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None, OPEN_EXISTING, OPEN_REPARSE_POINT, None,
        )
        if path_handle in (None, invalid):
            raise StableHandleRefused("K1_PATH_IDENTITY_HANDLE_REFUSED")
        try:
            path_metadata = Info()
            if not get_info(path_handle, ctypes.byref(path_metadata)):
                raise StableHandleRefused("K1_PATH_IDENTITY_UNAVAILABLE")
            native_pinned_id = (
                metadata.dwVolumeSerialNumber,
                metadata.nFileIndexHigh, metadata.nFileIndexLow,
            )
            native_path_id = (
                path_metadata.dwVolumeSerialNumber,
                path_metadata.nFileIndexHigh, path_metadata.nFileIndexLow,
            )
            if native_pinned_id != native_path_id:
                raise StableHandleRefused("K1_NATIVE_FILE_IDENTITY_MISMATCH")
            if (path_metadata.dwFileAttributes & (
                    REPARSE_ATTRIBUTE | DIRECTORY_ATTRIBUTE)
                    or path_metadata.nNumberOfLinks != 1):
                raise StableHandleRefused("K1_NATIVE_PATH_REDIRECT_REFUSED")
        finally:
            close(path_handle)

        # Transferring ownership of HANDLE to a Python descriptor.
        fd = msvcrt.open_osfhandle(
            int(raw_file), os.O_RDWR | getattr(os, "O_BINARY", 0)
        )
        raw_file = None
        with os.fdopen(fd, "r+b", buffering=0) as stream:
            if hashlib.sha256(stream.read()).hexdigest() != expected[0]:
                raise StableHandleRefused("K1_PINNED_FILE_PREIMAGE_MISMATCH")

            # Parent directory handles and file sharing now stop relocation.
            if attest(root, relative.as_posix()) != expected:
                raise StableHandleRefused("K1_PINNED_PATH_ATTESTATION_MISMATCH")

            stream.seek(0)
            wrote = True
            count = stream.write(payload)
            if count != len(payload):
                raise OSError("K1_PINNED_WRITE_INCOMPLETE")
            stream.truncate(len(payload))
            stream.flush()
            os.fsync(stream.fileno())
            return len(payload)
    except StableHandleRefused:
        raise
    except Exception as exc:
        if not wrote:
            raise StableHandleRefused("K1_STABLE_HANDLE_PREWRITE_FAILURE") from exc
        raise
    finally:
        if raw_file not in (None, invalid):
            close(raw_file)
        for parent in reversed(parents):
            close(parent)
