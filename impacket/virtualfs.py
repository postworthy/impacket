"""Virtual filesystem support for the Impacket SMB server.

This module provides a small in-memory filesystem that can be used to serve
content without touching the local disk. The filesystem is intentionally kept
simple: it is hierarchical, read-only, and thread-safe. It can be populated via
direct API calls or by loading a JSON dictionary.

Example:

.. code-block:: python

    from impacket.virtualfs import VirtualFS, add_virtual_share

    vfs = VirtualFS()
    vfs.add_dir('test')
    vfs.add_file('test/test.txt', b'hello world')

    add_virtual_share('virtual_share_root', vfs, share_name='SHARE')

When the SMB server is configured with a share whose path is
``virtual_share_root`` the filesystem operations for that path are satisfied
from memory. The existing SMB packet handling code is untouched; only the data
source backing the share is swapped.

To exercise the share with ``smbclient`` after starting the server, run::

    smbclient //127.0.0.1/SHARE -N -c 'ls; get test/test.txt -'

Environment variables:

* ``SMBSERVER_VFS`` – enable automatic registration when set to ``1``/``true``.
* ``SMBSERVER_VFS_ROOT`` – share path to attach the virtual filesystem to.
* ``SMBSERVER_VFS_JSON`` or ``SMBSERVER_VFS_JSON_FILE`` – optional JSON
  document (or path to a JSON file) describing the virtual tree.
* ``SMBSERVER_VFS_SHARE`` – optional SMB share name for registration.
"""

from __future__ import annotations

import errno
import json
import logging
import os
import stat
import threading
import time
from itertools import count
from typing import Dict, List, Optional, Tuple

LOG = logging.getLogger(__name__)


def _normalize_local_path(path: str) -> str:
    """Return a normalized version of *path* using the current OS conventions."""

    if path is None:
        raise ValueError("path cannot be None")

    normalized = os.path.normpath(path.replace("\\", os.sep))
    if normalized == '.':
        return ''
    return normalized


class VirtualNode:
    """Base class for virtual filesystem nodes."""

    def __init__(
        self,
        name: str,
        mode: int,
        inode: int,
        atime: Optional[float] = None,
        mtime: Optional[float] = None,
        ctime: Optional[float] = None,
    ) -> None:
        now = time.time()
        self.name = name
        self.mode = mode
        self.inode = inode
        self.atime = now if atime is None else atime
        self.mtime = now if mtime is None else mtime
        self.ctime = now if ctime is None else ctime

    def stat(self) -> os.stat_result:
        raise NotImplementedError


class VirtualDirectory(VirtualNode):
    def __init__(self, name: str, inode: int, mode: int = stat.S_IFDIR | 0o755) -> None:
        super().__init__(name, mode, inode)
        self.children: Dict[str, VirtualNode] = {}

    def stat(self) -> os.stat_result:
        nlink = 2
        size = 0
        return os.stat_result((self.mode, self.inode, 0, nlink, 0, 0, size, self.atime, self.mtime, self.ctime))


class VirtualFile(VirtualNode):
    def __init__(
        self,
        name: str,
        inode: int,
        content: bytes,
        mode: int = stat.S_IFREG | 0o644,
        atime: Optional[float] = None,
        mtime: Optional[float] = None,
        ctime: Optional[float] = None,
    ) -> None:
        super().__init__(name, mode, inode, atime=atime, mtime=mtime, ctime=ctime)
        self.content = content

    def stat(self) -> os.stat_result:
        size = len(self.content)
        return os.stat_result((self.mode, self.inode, 0, 1, 0, 0, size, self.atime, self.mtime, self.ctime))


class VirtualHandle:
    """A lightweight file-like object for VirtualFile instances."""

    def __init__(self, node: VirtualFile) -> None:
        self._node = node
        self._position = 0
        self._closed = False
        self._lock = threading.RLock()

    def read(self, size: int) -> bytes:
        with self._lock:
            if self._closed:
                raise ValueError("I/O operation on closed virtual file")
            if size < 0:
                size = len(self._node.content) - self._position
            end = self._position + size
            data = self._node.content[self._position:end]
            self._position += len(data)
            self._node.atime = time.time()
            return data

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        with self._lock:
            if self._closed:
                raise ValueError("I/O operation on closed virtual file")

            if whence == os.SEEK_SET:
                new_position = offset
            elif whence == os.SEEK_CUR:
                new_position = self._position + offset
            elif whence == os.SEEK_END:
                new_position = len(self._node.content) + offset
            else:
                raise ValueError(f"invalid whence: {whence}")

            if new_position < 0:
                raise ValueError("negative seek position")

            self._position = new_position
            return self._position

    def close(self) -> None:
        with self._lock:
            self._closed = True

    def fileno(self) -> int:
        raise OSError(errno.EBADF, os.strerror(errno.EBADF))


class VirtualFS:
    """A minimal in-memory filesystem tree."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._inode_counter = count(1)
        self._root = VirtualDirectory('', next(self._inode_counter))

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------
    def _split(self, path: str) -> List[str]:
        normalized = _normalize_local_path(path)
        if normalized in ('', os.sep):
            return []
        parts = [part for part in normalized.split(os.sep) if part]
        return parts

    def _get_node(self, path: str) -> Optional[VirtualNode]:
        parts = self._split(path)
        node: VirtualNode = self._root
        with self._lock:
            for part in parts:
                if not isinstance(node, VirtualDirectory):
                    return None
                child = node.children.get(part)
                if child is None:
                    return None
                node = child
            return node

    def _ensure_directory(self, path: str) -> VirtualDirectory:
        parts = self._split(path)
        node: VirtualDirectory = self._root
        with self._lock:
            for part in parts:
                child = node.children.get(part)
                if child is None:
                    child = VirtualDirectory(part, next(self._inode_counter))
                    node.children[part] = child
                if not isinstance(child, VirtualDirectory):
                    raise OSError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), path)
                node = child
            return node

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def add_dir(self, path: str) -> None:
        self._ensure_directory(path)

    def add_file(
        self,
        path: str,
        content: bytes | str,
        *,
        mode: int = stat.S_IFREG | 0o644,
        mtime: Optional[float] = None,
        atime: Optional[float] = None,
        ctime: Optional[float] = None,
    ) -> None:
        if isinstance(content, str):
            content_bytes = content.encode('utf-8')
        else:
            content_bytes = content

        directory, _, name = _normalize_local_path(path).rpartition(os.sep)
        if not name:
            raise ValueError("file name cannot be empty")
        parent = self._ensure_directory(directory)
        with self._lock:
            parent.children[name] = VirtualFile(
                name,
                next(self._inode_counter),
                content_bytes,
                mode=mode,
                atime=atime,
                mtime=mtime,
                ctime=ctime,
            )

    def listdir(self, path: str) -> List[str]:
        node = self._get_node(path)
        if node is None:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)
        if not isinstance(node, VirtualDirectory):
            raise NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), path)
        with self._lock:
            return list(node.children.keys())

    def exists(self, path: str) -> bool:
        node = self._get_node(path)
        return node is not None

    def isdir(self, path: str) -> bool:
        node = self._get_node(path)
        return isinstance(node, VirtualDirectory)

    def isfile(self, path: str) -> bool:
        node = self._get_node(path)
        return isinstance(node, VirtualFile)

    def stat(self, path: str) -> os.stat_result:
        if path in ('', '.'):  # Root special case
            node = self._root
        else:
            node = self._get_node(path)
        if node is None:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)
        return node.stat()

    def open(self, path: str) -> VirtualHandle:
        node = self._get_node(path)
        if node is None:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)
        if not isinstance(node, VirtualFile):
            raise IsADirectoryError(errno.EISDIR, os.strerror(errno.EISDIR), path)
        return VirtualHandle(node)

    # ------------------------------------------------------------------
    # Bulk population helpers
    # ------------------------------------------------------------------
    def populate(self, tree: Dict[str, object]) -> None:
        """Populate the filesystem from a nested dictionary.

        The dictionary keys act as directory or file names. If the value is a
        mapping, a directory is created recursively. If the value is a string or
        bytes, a file is created with that content. If the value is a mapping
        that contains a ``content`` key, the value is treated as file metadata.
        """

        def _populate(current_path: str, subtree: Dict[str, object]) -> None:
            for name, value in subtree.items():
                child_path = os.path.join(current_path, name) if current_path else name
                if isinstance(value, dict) and 'content' not in value:
                    self.add_dir(child_path)
                    _populate(child_path, value)
                else:
                    if isinstance(value, dict):
                        content = value.get('content', b'')
                        mtime = value.get('mtime')
                        atime = value.get('atime')
                        ctime = value.get('ctime')
                    else:
                        content = value
                        mtime = atime = ctime = None
                    self.add_file(child_path, content, mtime=mtime, atime=atime, ctime=ctime)

        _populate('', tree)

    @classmethod
    def from_dict(cls, tree: Dict[str, object]) -> "VirtualFS":
        instance = cls()
        instance.populate(tree)
        return instance

    @classmethod
    def from_json(cls, data: str) -> "VirtualFS":
        tree = json.loads(data)
        if not isinstance(tree, dict):
            raise ValueError("JSON specification must describe a dictionary")
        return cls.from_dict(tree)


class _VirtualShareEntry:
    def __init__(self, path: str, vfs: VirtualFS, share_name: Optional[str] = None) -> None:
        self.path = _normalize_local_path(path)
        self.path_casefold = os.path.normcase(self.path)
        self.casefold_with_sep = self.path_casefold + os.path.normcase(os.sep)
        self.vfs = vfs
        self.share_name = share_name.upper() if share_name else None


_registry_lock = threading.RLock()
_virtual_shares_by_path: Dict[str, _VirtualShareEntry] = {}
_virtual_shares_by_name: Dict[str, _VirtualShareEntry] = {}


def add_virtual_share(path: str, vfs: VirtualFS, share_name: Optional[str] = None) -> None:
    """Register *vfs* as the handler for filesystem operations under *path*."""

    entry = _VirtualShareEntry(path, vfs, share_name=share_name)
    with _registry_lock:
        _virtual_shares_by_path[entry.path_casefold] = entry
        if entry.share_name:
            _virtual_shares_by_name[entry.share_name] = entry


def remove_virtual_share(path: str) -> None:
    normalized = _normalize_local_path(path)
    key = os.path.normcase(normalized)
    with _registry_lock:
        entry = _virtual_shares_by_path.pop(key, None)
        if entry and entry.share_name:
            _virtual_shares_by_name.pop(entry.share_name, None)


def get_virtual_share_for_name(name: str) -> Optional[VirtualFS]:
    with _registry_lock:
        entry = _virtual_shares_by_name.get(name.upper())
        return entry.vfs if entry else None


def _match_virtual_share(path: str) -> Tuple[Optional[_VirtualShareEntry], Optional[str]]:
    normalized = _normalize_local_path(path)
    normcase_path = os.path.normcase(normalized)
    raw_path = path.replace("\\", os.sep)
    normcase_raw_path = os.path.normcase(raw_path)
    with _registry_lock:
        for entry in _virtual_shares_by_path.values():
            if normcase_path == entry.path_casefold or normcase_raw_path == entry.path_casefold:
                return entry, ''
            if normcase_path.startswith(entry.casefold_with_sep) or normcase_raw_path.startswith(entry.casefold_with_sep):
                if normcase_raw_path.startswith(entry.casefold_with_sep):
                    relative = raw_path[len(entry.path):]
                else:
                    relative = normalized[len(entry.path):]
                if relative.startswith(os.sep):
                    relative = relative[len(os.sep):]
                relative = _normalize_local_path(relative)
                if relative.startswith('..'):
                    relative = ''
                return entry, relative
    return None, None


def vfs_exists(path: str) -> bool:
    entry, relative = _match_virtual_share(path)
    if entry:
        return relative == '' or entry.vfs.exists(relative)
    return os.path.exists(path)


def vfs_isdir(path: str) -> bool:
    entry, relative = _match_virtual_share(path)
    if entry:
        return entry.vfs.isdir(relative or '')
    return os.path.isdir(path)


def vfs_isfile(path: str) -> bool:
    entry, relative = _match_virtual_share(path)
    if entry:
        return entry.vfs.isfile(relative or '')
    return os.path.isfile(path)


def vfs_listdir(path: str) -> List[str]:
    entry, relative = _match_virtual_share(path)
    if entry:
        return entry.vfs.listdir(relative or '')
    return os.listdir(path)


def vfs_stat(path: str) -> os.stat_result:
    entry, relative = _match_virtual_share(path)
    if entry:
        return entry.vfs.stat(relative or '')
    return os.stat(path)


def vfs_getsize(path: str) -> int:
    return vfs_stat(path).st_size


def vfs_open(path: str, flags: int, mode: int = 0o777):
    entry, relative = _match_virtual_share(path)
    if entry:
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            raise OSError(errno.EROFS, os.strerror(errno.EROFS), path)
        return entry.vfs.open(relative or '')
    return os.open(path, flags, mode)


def vfs_read(handle, size: int) -> bytes:
    if isinstance(handle, VirtualHandle):
        return handle.read(size)
    return os.read(handle, size)


def vfs_lseek(handle, offset: int, whence: int = os.SEEK_SET) -> int:
    if isinstance(handle, VirtualHandle):
        return handle.seek(offset, whence)
    return os.lseek(handle, offset, whence)


def vfs_write(handle, data: bytes) -> int:
    if isinstance(handle, VirtualHandle):
        raise OSError(errno.EROFS, os.strerror(errno.EROFS))
    return os.write(handle, data)


def vfs_close(handle) -> None:
    if isinstance(handle, VirtualHandle):
        handle.close()
    else:
        os.close(handle)


def vfs_remove(path: str) -> None:
    entry, _ = _match_virtual_share(path)
    if entry:
        raise OSError(errno.EROFS, os.strerror(errno.EROFS), path)
    os.remove(path)


def vfs_mkdir(path: str, mode: int = 0o777) -> None:
    entry, _ = _match_virtual_share(path)
    if entry:
        raise OSError(errno.EROFS, os.strerror(errno.EROFS), path)
    os.mkdir(path, mode)


def vfs_rmdir(path: str) -> None:
    entry, _ = _match_virtual_share(path)
    if entry:
        raise OSError(errno.EROFS, os.strerror(errno.EROFS), path)
    os.rmdir(path)


def vfs_rename(src: str, dst: str) -> None:
    entry_src, _ = _match_virtual_share(src)
    entry_dst, _ = _match_virtual_share(dst)
    if entry_src or entry_dst:
        raise OSError(errno.EROFS, os.strerror(errno.EROFS), src)
    os.rename(src, dst)


def vfs_rmtree(path: str) -> None:
    entry, _ = _match_virtual_share(path)
    if entry:
        raise OSError(errno.EROFS, os.strerror(errno.EROFS), path)
    import shutil

    shutil.rmtree(path)


def register_virtual_share_from_env() -> None:
    if os.environ.get('SMBSERVER_VFS', '').lower() not in {'1', 'true', 'yes', 'on'}:
        return

    root = os.environ.get('SMBSERVER_VFS_ROOT')
    if not root:
        LOG.debug("SMBSERVER_VFS set but SMBSERVER_VFS_ROOT is missing")
        return

    data = os.environ.get('SMBSERVER_VFS_JSON')
    json_file = os.environ.get('SMBSERVER_VFS_JSON_FILE')
    if json_file and not data:
        try:
            with open(json_file, 'r', encoding='utf-8') as handle:
                data = handle.read()
        except OSError as exc:
            LOG.warning("Failed to read virtual filesystem JSON file %s: %s", json_file, exc)

    vfs = VirtualFS()
    if data:
        try:
            vfs = VirtualFS.from_json(data)
        except Exception as exc:
            LOG.warning("Failed to load virtual filesystem from JSON: %s", exc)
            vfs = VirtualFS()

    add_virtual_share(root, vfs, share_name=os.environ.get('SMBSERVER_VFS_SHARE'))


register_virtual_share_from_env()


__all__ = [
    'VirtualFS',
    'VirtualHandle',
    'add_virtual_share',
    'remove_virtual_share',
    'get_virtual_share_for_name',
    'vfs_exists',
    'vfs_isdir',
    'vfs_isfile',
    'vfs_listdir',
    'vfs_stat',
    'vfs_getsize',
    'vfs_open',
    'vfs_read',
    'vfs_lseek',
    'vfs_write',
    'vfs_close',
    'vfs_remove',
    'vfs_mkdir',
    'vfs_rmdir',
    'vfs_rename',
    'vfs_rmtree',
    'register_virtual_share_from_env',
]