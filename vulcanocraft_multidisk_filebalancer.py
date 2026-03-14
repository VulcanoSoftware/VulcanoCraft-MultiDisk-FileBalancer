import os
from datetime import datetime, timedelta
import shutil
import yaml
import time
import requests
import threading
import asyncio
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote, urlparse, parse_qs
import asyncssh
import stat
import errno
import sys
import hashlib
import signal
import atexit
import subprocess
import ctypes
from asyncssh.sftp import SFTPName, SFTPAttrs, FXF_READ, FXF_WRITE, FXF_APPEND, FXF_CREAT, FXF_TRUNC

def try_import_fuse():
    global FUSE, Operations, FuseOSError
    try:
        from fuse import FUSE, Operations, FuseOSError
        return True
    except (ImportError, OSError):
        FUSE = None
        Operations = object
        class FuseOSError(Exception):
            pass
        return False

FUSE = None
Operations = object
class FuseOSError(Exception):
    pass

try_import_fuse()

def has_admin_privileges():
    if os.name == 'nt':
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    geteuid = getattr(os, 'geteuid', None)
    if geteuid is None:
        return False
    try:
        return geteuid() == 0
    except Exception:
        return False


def is_privilege_error_text(text):
    message = str(text).lower()
    privilege_markers = [
        "permission denied",
        "access is denied",
        "administrator",
        "admin privileges",
        "requires elevation",
        "operation not permitted",
        "must be run as root",
        "not in the sudoers",
        "authentication is required",
        "insufficient privileges",
    ]
    return any(marker in message for marker in privilege_markers)


def admin_restart_instruction():
    if os.name == 'nt':
        return "Restart this program as Administrator and try again."
    return "Restart this program with sudo/root privileges and try again."


def detect_fuse_install_strategy():
    import platform
    system = platform.system().lower()
    if system == "linux":
        if shutil.which("apt-get"):
            return "apt-get install libfuse2"
        if shutil.which("dnf"):
            return "dnf install fuse-libs"
        if shutil.which("pacman"):
            return "pacman install fuse2"
        return "no supported Linux package manager detected"
    if system == "windows":
        if shutil.which("winget"):
            return "winget install WinFsp.WinFsp"
        return "PowerShell download and silent install of WinFsp"
    if system == "darwin":
        if shutil.which("brew"):
            return "brew install --cask macfuse"
        return "direct macFUSE dmg install"
    return "unsupported operating system for automatic FUSE installer"


def print_startup_preflight(webhook_url, fuse_enabled, webdav_enabled, sftp_enabled, fuse_mount_point):
    import platform
    os_name = platform.system()
    os_release = platform.release()
    py_version = platform.python_version()
    admin_mode = "yes" if has_admin_privileges() else "no"
    fuse_loaded = "yes" if FUSE is not None else "no"
    fuse_required = "yes" if fuse_enabled else "no"
    install_strategy = detect_fuse_install_strategy()
    print_and_discord("========== Startup preflight ==========", webhook_url)
    print_and_discord(f"OS: {os_name} {os_release}", webhook_url)
    print_and_discord(f"Python: {py_version}", webhook_url)
    print_and_discord(f"Admin/root privileges: {admin_mode}", webhook_url)
    print_and_discord(f"Features enabled -> FUSE: {fuse_required}, WebDAV: {'yes' if webdav_enabled else 'no'}, SFTP: {'yes' if sftp_enabled else 'no'}", webhook_url)
    print_and_discord(f"FUSE python binding loaded: {fuse_loaded}", webhook_url)
    if fuse_enabled:
        print_and_discord(f"FUSE mount point: {fuse_mount_point}", webhook_url)
        print_and_discord(f"FUSE installer strategy: {install_strategy}", webhook_url)
    print_and_discord("=======================================", webhook_url)


def install_libfuse():
    import platform
    system = platform.system().lower()
    print(f"Attempting to install libfuse for {system}...")
    last_error = ""

    def run_cmd(cmd, shell=False):
        nonlocal last_error
        result = subprocess.run(cmd, check=True, shell=shell, capture_output=True, text=True)
        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        last_error = stderr or stdout

    def install_python_fuse_package():
        nonlocal last_error
        pip_cmd = [sys.executable, "-m", "pip", "install", "fusepy"]
        result = subprocess.run(pip_cmd, capture_output=True, text=True)
        if result.returncode == 0:
            return True
        last_error = (result.stderr or result.stdout or "").strip()
        pip_cmd_break = [sys.executable, "-m", "pip", "install", "fusepy", "--break-system-packages"]
        result_break = subprocess.run(pip_cmd_break, capture_output=True, text=True)
        if result_break.returncode == 0:
            return True
        last_error = (result_break.stderr or result_break.stdout or last_error).strip()
        return False

    try:
        if system == "linux":
            if shutil.which("apt-get"):
                run_cmd(["sudo", "apt-get", "update"])
                run_cmd(["sudo", "apt-get", "install", "-y", "libfuse2"])
            elif shutil.which("dnf"):
                run_cmd(["sudo", "dnf", "install", "-y", "fuse-libs"])
            elif shutil.which("pacman"):
                run_cmd(["sudo", "pacman", "-S", "--noconfirm", "fuse2"])
            else:
                print("No supported package manager (apt, dnf, pacman) found on Linux.")
                return False, "No supported Linux package manager found for FUSE installation.", False

        elif system == "windows":
            if shutil.which("winget"):
                run_cmd(["winget", "install", "--id", "WinFsp.WinFsp", "--accept-package-agreements", "--accept-source-agreements"])
            else:
                print("winget not found. Attempting direct installation of WinFsp via PowerShell...")
                # WinFsp v2.0 release
                winfsp_url = "https://github.com/winfsp/winfsp/releases/download/v2.0/winfsp-2.0.23075.msi"
                ps_cmd = f"Invoke-WebRequest -Uri {winfsp_url} -OutFile winfsp.msi; Start-Process msiexec.exe -ArgumentList '/i winfsp.msi /quiet /norestart' -Wait; Remove-Item winfsp.msi"
                run_cmd(["powershell", "-Command", ps_cmd])

        elif system == "darwin":
            if shutil.which("brew"):
                run_cmd(["brew", "install", "--cask", "macfuse"])
            else:
                print("Homebrew not found. Attempting direct installation of macFUSE...")
                # macFUSE v4.8.3
                macfuse_url = "https://github.com/osxfuse/osxfuse/releases/download/macfuse-4.8.3/macfuse-4.8.3.dmg"
                run_cmd(["curl", "-L", "-o", "macfuse.dmg", macfuse_url])
                run_cmd(["hdiutil", "attach", "macfuse.dmg"])
                # We expect the volume name to be macFUSE
                run_cmd(r"sudo installer -pkg /Volumes/macFUSE/Install\ macFUSE.pkg -target /", shell=True)
                run_cmd(["hdiutil", "detach", "/Volumes/macFUSE"])
                run_cmd(["rm", "macfuse.dmg"])
        else:
            return False, f"Unsupported operating system for automatic FUSE installation: {system}", False

        if not install_python_fuse_package():
            needs_admin = is_privilege_error_text(last_error) or not has_admin_privileges()
            return False, (last_error or "Could not install Python package 'fusepy'."), needs_admin

        if try_import_fuse():
            return True, "", False
        return False, "FUSE dependencies were installed but Python still cannot load FUSE on this OS.", False
    except subprocess.CalledProcessError as e:
        combined_error = "\n".join(
            part for part in [str(e), getattr(e, "stderr", ""), getattr(e, "stdout", ""), last_error] if part
        ).strip()
        needs_admin = is_privilege_error_text(combined_error) or not has_admin_privileges()
        print(f"Automatic installation failed: {combined_error}")
        return False, combined_error, needs_admin
    except Exception as e:
        error_text = str(e)
        needs_admin = is_privilege_error_text(error_text) or not has_admin_privileges()
        print(f"Automatic installation failed: {error_text}")
        return False, error_text, needs_admin

current_dir = os.getcwd()
config_path = os.path.join(current_dir, "config.yml")

_vfs_base_paths = []
_vfs_base_paths_lock = threading.Lock()
_flat_root_file_map_cache = {}
_flat_root_file_map_last_refresh = 0.0
_flat_root_file_map_needs_refresh = True
_flat_root_file_map_lock = threading.Lock()
_flat_root_file_map_ttl_seconds = 2.0


def set_vfs_base_paths(paths):
    global _flat_root_file_map_needs_refresh
    with _vfs_base_paths_lock:
        _vfs_base_paths.clear()
        _vfs_base_paths.extend(p for p in paths if p)
    with _flat_root_file_map_lock:
        _flat_root_file_map_needs_refresh = True


def get_vfs_base_paths():
    with _vfs_base_paths_lock:
        return list(_vfs_base_paths)


def _normalized_existing_path_entries(paths):
    normalized_paths = []
    seen = set()
    for path in paths:
        if not path:
            continue
        normalized = os.path.normcase(os.path.normpath(str(path)))
        if normalized in seen:
            continue
        seen.add(normalized)
        normalized_paths.append(path)
    return normalized_paths


def build_vfs_base_paths(src_folders, disks, extra_paths=None):
    all_paths = list(src_folders)
    all_paths.extend(d.get('path') or d.get('pad') for d in disks if isinstance(d, dict))
    if extra_paths:
        all_paths.extend(extra_paths)
    return _normalized_existing_path_entries(all_paths)


def normalize_virtual_path(virtual_path):
    if not virtual_path:
        return '/'
    path = virtual_path.strip()
    if not path.startswith('/'):
        path = '/' + path
    return path


def _build_flat_file_map(base_paths):
    flat_map = {}
    basename_records = {}
    seen_physical_paths = set()
    for base in base_paths:
        if not os.path.isdir(base):
            continue
        try:
            for root, _dirs, files in os.walk(base, onerror=lambda _exc: None):
                for file_name in files:
                    physical_path = os.path.join(root, file_name)
                    norm_path = os.path.normcase(os.path.normpath(physical_path))
                    if norm_path in seen_physical_paths:
                        continue
                    seen_physical_paths.add(norm_path)
                    basename_records.setdefault(file_name, []).append(physical_path)
        except OSError:
            continue

    for file_name, physical_paths in basename_records.items():
        if len(physical_paths) == 1:
            flat_map[file_name] = physical_paths[0]
            continue
        stem, ext = os.path.splitext(file_name)
        for physical_path in physical_paths:
            path_hash = hashlib.sha1(physical_path.encode('utf-8', errors='ignore')).hexdigest()[:8]
            virtual_name = f"{stem}__{path_hash}{ext}"
            flat_map[virtual_name] = physical_path

    return flat_map


def _build_flat_root_file_map():
    return get_flat_root_file_map()


def get_flat_root_file_map(force_refresh=False):
    global _flat_root_file_map_cache, _flat_root_file_map_last_refresh, _flat_root_file_map_needs_refresh
    now = time.time()
    with _flat_root_file_map_lock:
        should_refresh = (
            force_refresh
            or _flat_root_file_map_needs_refresh
            or (now - _flat_root_file_map_last_refresh) > _flat_root_file_map_ttl_seconds
        )
    if should_refresh:
        fresh_map = _build_flat_file_map(get_vfs_base_paths())
        with _flat_root_file_map_lock:
            _flat_root_file_map_cache = fresh_map
            _flat_root_file_map_last_refresh = time.time()
            _flat_root_file_map_needs_refresh = False
            return dict(_flat_root_file_map_cache)
    with _flat_root_file_map_lock:
        return dict(_flat_root_file_map_cache)


def get_virtual_item_info(virtual_path):
    """Returns (is_file, is_dir, physical_path) for a virtual path."""
    virt = normalize_virtual_path(virtual_path)
    if virt == '/':
        return False, True, None
    rel = virt.lstrip('/')
    if rel and '/' not in rel and '\\' not in rel:
        flat_root_files = _build_flat_root_file_map()
        if rel in flat_root_files:
            return True, False, flat_root_files[rel]
    for base in get_vfs_base_paths():
        candidate = os.path.join(base, rel)
        if os.path.isfile(candidate):
            return True, False, candidate
        if os.path.isdir(candidate):
            return False, True, candidate
    return False, False, None


def list_virtual_dir(virtual_dir):
    """Returns a dictionary mapping names to full virtual paths for children of virtual_dir."""
    virt_dir = normalize_virtual_path(virtual_dir)
    if virt_dir == '/':
        flat_root_files = _build_flat_root_file_map()
        return {name: '/' + name for name in flat_root_files}
    rel = virt_dir.lstrip('/')
    seen = {}
    for base in get_vfs_base_paths():
        scan_path = os.path.join(base, rel) if rel else base
        if not os.path.isdir(scan_path):
            continue
        try:
            for name in os.listdir(scan_path):
                if name not in seen:
                    full_virtual = virt_dir.rstrip('/') + '/' + name
                    seen[name] = full_virtual
        except OSError:
            continue
    return seen


def get_physical_path_for_virtual(virtual_path):
    is_file, _is_dir, physical_path = get_virtual_item_info(virtual_path)
    if is_file:
        return physical_path
    return None

def start_webdav_server_thread(webdav_config, upload_src_path, webhook_url, serve_root_path=None):
    if not webdav_config.get('enabled', False):
        return
    
    try:
        from wsgidav.wsgidav_app import WsgiDAVApp
        from cheroot import wsgi
    except ImportError:
        print_and_discord("WebDAV error: 'wsgidav' or 'cheroot' not installed. Check requirements.txt.", webhook_url)
        return

    host = webdav_config.get('host', '0.0.0.0')
    port = int(webdav_config.get('port', 8080))
    username = webdav_config.get('username')
    password = webdav_config.get('password')
    
    # Use FUSE mount path if provided, otherwise fallback to upload_src
    dav_root = serve_root_path if serve_root_path else upload_src_path
    
    auth_config = {"user_mapping": {"*": True}}
    if username and password:
        auth_config = {"user_mapping": {"*": {username: {"password": password}}}}

    config = {
        "host": host,
        "port": port,
        "provider_mapping": {"/": dav_root},
        "simple_dc": auth_config,
        "verbose": 1,
    }

    app = WsgiDAVApp(config)

    def run_server():
        try:
            server = wsgi.Server((host, port), app)
            print_and_discord(f"WebDAV server started on {host}:{port}", webhook_url)
            server.start()
        except Exception as e:
            print_and_discord(f"Could not start WebDAV server: {e}", webhook_url)

    threading.Thread(target=run_server, daemon=True).start()


class SimpleSSHServer(asyncssh.SSHServer):
    def __init__(self, username, password, webhook_url):
        self._username = username
        self._password = password
        self._webhook_url = webhook_url

    def connection_made(self, conn):
        peer = conn.get_extra_info('peername')
        local = conn.get_extra_info('sockname')
        print_and_discord(f"SSH connection received from {peer} to local address {local}", self._webhook_url)

    def connection_lost(self, exc):
        if exc:
            print_and_discord(f"SSH connection lost with error: {exc}", self._webhook_url)
        else:
            print_and_discord(f"SSH connection closed", self._webhook_url)

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        is_valid = (username == self._username and password == self._password)
        if not is_valid:
            print_and_discord(f"SFTP login failed for user: {username}", self._webhook_url)
        else:
            print_and_discord(f"SFTP login successful for user: {username}", self._webhook_url)
        return is_valid

class SimpleSFTPServer(asyncssh.SFTPServer):
    def __init__(self, chan, upload_src_path, serve_root_path=None, serve_root_flat=False, serve_global_flat=False):
        self._upload_src_path = upload_src_path
        self._serve_root_path = os.path.normpath(serve_root_path) if serve_root_path else None
        self._serve_root_flat = bool(serve_root_flat and self._serve_root_path)
        self._serve_global_flat = bool(serve_global_flat)
        os.makedirs(self._upload_src_path, exist_ok=True)
        super().__init__(chan)

    def _normalize_virtual(self, path):
        if isinstance(path, bytes):
            path_str = path.decode('utf-8', errors='ignore')
        else:
            path_str = str(path)
        if path_str in ('', '.', './', '/.', '/'):
            return '/'
        return normalize_virtual_path(path_str)

    def _upload_physical_path(self, virt):
        rel = virt.lstrip('/')
        return os.path.join(self._upload_src_path, rel) if rel else self._upload_src_path

    def _resolve_under_root(self, virt):
        if not self._serve_root_path:
            return False, False, None
        if virt == '/':
            return False, True, self._serve_root_path
        rel = virt.lstrip('/').replace('/', os.sep)
        candidate = os.path.normpath(os.path.join(self._serve_root_path, rel))
        root_norm = os.path.normcase(os.path.normpath(self._serve_root_path))
        candidate_norm = os.path.normcase(candidate)
        if candidate_norm != root_norm and not candidate_norm.startswith(root_norm + os.sep):
            return False, False, None
        if os.path.isfile(candidate):
            return True, False, candidate
        if os.path.isdir(candidate):
            return False, True, candidate
        return False, False, None

    def _resolve_virtual_item(self, virt):
        if self._serve_global_flat:
            if virt == '/':
                return False, True, None
            rel = virt.lstrip('/')
            if rel and '/' not in rel and '\\' not in rel:
                flat_files = get_flat_root_file_map()
                physical_path = flat_files.get(rel)
                if physical_path:
                    return True, False, physical_path
            return False, False, None
        if not self._serve_root_path:
            return get_virtual_item_info(virt)
        rel = virt.lstrip('/')
        if self._serve_root_flat and rel and '/' not in rel and '\\' not in rel:
            flat_files = _build_flat_file_map([self._serve_root_path])
            physical_path = flat_files.get(rel)
            if physical_path:
                return True, False, physical_path
        return self._resolve_under_root(virt)

    def canonicalize(self, path):
        virt = self._normalize_virtual(path)
        return virt.encode('utf-8')

    def realpath(self, path):
        virt = self._normalize_virtual(path)
        return virt.encode('utf-8')

    async def scandir(self, path):
        virt_dir = self._normalize_virtual(path)
        flat_files_snapshot = None
        if self._serve_global_flat and virt_dir == '/':
            flat_files_snapshot = get_flat_root_file_map()
            names = {name: '/' + name for name in flat_files_snapshot}
        elif self._serve_root_path and self._serve_root_flat and virt_dir == '/':
            names = {name: '/' + name for name in _build_flat_file_map([self._serve_root_path])}
        elif self._serve_global_flat:
            names = {}
        elif self._serve_root_path:
            is_file, is_dir, scan_path = self._resolve_under_root(virt_dir)
            if not is_dir or not scan_path or not os.path.isdir(scan_path):
                names = {}
            else:
                names = {}
                try:
                    for name in os.listdir(scan_path):
                        names[name] = virt_dir.rstrip('/') + '/' + name
                except OSError:
                    names = {}
        else:
            names = list_virtual_dir(virt_dir)

        # Add standard directory entries
        for name in ('.', '..'):
            now = int(time.time())
            attrs = SFTPAttrs(permissions=stat.S_IFDIR | 0o755, atime=now, mtime=now, size=0)
            yield SFTPName(name.encode('utf-8'), None, attrs)

        for name, full_virtual in names.items():
            if flat_files_snapshot is not None and name in flat_files_snapshot:
                is_file, is_dir, physical_path = True, False, flat_files_snapshot.get(name)
            else:
                is_file, is_dir, physical_path = self._resolve_virtual_item(full_virtual)
            if physical_path and os.path.exists(physical_path):
                st = os.stat(physical_path)
                attrs = SFTPAttrs.from_local(st)
            else:
                mode = stat.S_IFDIR | 0o755 if is_dir else stat.S_IFREG | 0o644
                now = int(time.time())
                attrs = SFTPAttrs(
                    permissions=mode,
                    atime=now,
                    mtime=now,
                    size=0
                )
            yield SFTPName(name.encode('utf-8'), None, attrs)

    async def _stat_helper(self, path, follow_symlinks=True):
        virt = self._normalize_virtual(path)
        is_file, is_dir, physical_path = self._resolve_virtual_item(virt)
        if physical_path and os.path.exists(physical_path):
            st = os.stat(physical_path) if follow_symlinks else os.lstat(physical_path)
            return SFTPAttrs.from_local(st)
        if is_dir:
            mode = stat.S_IFDIR | 0o755
            now = int(time.time())
            return SFTPAttrs(permissions=mode, atime=now, mtime=now, size=0)
        raise asyncssh.SFTPNoSuchFile(virt)

    async def stat(self, path):
        return await self._stat_helper(path, follow_symlinks=True)

    async def lstat(self, path):
        return await self._stat_helper(path, follow_symlinks=False)

    def _mode_from_pflags(self, pflags):
        read = bool(pflags & FXF_READ)
        write = bool(pflags & FXF_WRITE)
        append = bool(pflags & FXF_APPEND)
        creat = bool(pflags & FXF_CREAT)
        trunc = bool(pflags & FXF_TRUNC)
        if read and not write:
            return 'rb'
        if write and not read:
            if append and not trunc:
                return 'ab'
            if trunc or creat:
                return 'wb'
            return 'wb'
        if read and write:
            if append and not trunc:
                return 'a+b'
            if trunc or creat:
                return 'w+b'
            return 'r+b'
        return 'rb'

    async def open(self, path, pflags, attrs):
        virt = self._normalize_virtual(path)
        write = bool(pflags & FXF_WRITE)
        if write:
            rel = virt.lstrip('/')
            if not rel:
                raise asyncssh.SFTPFailure('Invalid file name')
            physical_path = os.path.join(self._upload_src_path, rel)
            os.makedirs(os.path.dirname(physical_path), exist_ok=True)
        else:
            is_file, _is_dir, physical_path = self._resolve_virtual_item(virt)
            if not physical_path or not os.path.exists(physical_path):
                raise asyncssh.SFTPNoSuchFile(virt)
        mode = self._mode_from_pflags(pflags)
        f = open(physical_path, mode)
        return f

    async def remove(self, path):
        virt = self._normalize_virtual(path)
        is_file, _is_dir, physical_path = self._resolve_virtual_item(virt)
        if physical_path and os.path.exists(physical_path):
            os.remove(physical_path)
            return
        raise asyncssh.SFTPNoSuchFile(virt)

    async def mkdir(self, path, attrs):
        virt = self._normalize_virtual(path)
        physical_path = self._upload_physical_path(virt)
        os.makedirs(physical_path, exist_ok=True)

    async def rmdir(self, path):
        virt = self._normalize_virtual(path)
        is_file, is_dir, physical_path = self._resolve_virtual_item(virt)
        if not is_dir:
            raise asyncssh.SFTPNoSuchFile(virt)
        if physical_path and os.path.isdir(physical_path):
            try:
                os.rmdir(physical_path)
            except OSError as exc:
                raise asyncssh.SFTPFailure(str(exc)) from exc
            return
        if self._serve_root_path:
            raise asyncssh.SFTPNoSuchFile(virt)
        rel = virt.lstrip('/')
        for base in get_vfs_base_paths():
            candidate = os.path.join(base, rel)
            if os.path.isdir(candidate):
                try:
                    os.rmdir(candidate)
                except OSError as exc:
                    raise asyncssh.SFTPFailure(str(exc)) from exc
                return
        raise asyncssh.SFTPNoSuchFile(virt)

    async def rename(self, oldpath, newpath, flags=0):
        old_virt = self._normalize_virtual(oldpath)
        new_virt = self._normalize_virtual(newpath)
        is_file, is_dir, old_physical = self._resolve_virtual_item(old_virt)
        if not old_physical or not os.path.exists(old_physical):
            raise asyncssh.SFTPNoSuchFile(old_virt)
        new_rel = new_virt.lstrip('/')
        new_physical = os.path.join(self._upload_src_path, new_rel)
        os.makedirs(os.path.dirname(new_physical), exist_ok=True)
        os.rename(old_physical, new_physical)

def start_sftp_server_thread(sftp_config, upload_src_path, webhook_url, serve_root_path=None, serve_root_flat=False, serve_global_flat=False):
    if not sftp_config.get('enabled', False):
        return

    host = sftp_config.get('host', '0.0.0.0')
    port = int(sftp_config.get('port', 2222))
    username_cfg = sftp_config.get('username', 'raiduser')
    password_cfg = sftp_config.get('password', 'changeme')
    host_key_path = sftp_config.get('host_key_path')

    async def start_server():
        try:
            import socket

            # Check if port is already in use
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind((host, port))
                except socket.error:
                    print_and_discord(f"ERROR: SFTP Port {port} is already in use by another process!", webhook_url)
                    print_and_discord(f"Use 'ss -tlnp | grep {port}' to find the conflicting process.", webhook_url)
                    return

            hostname = socket.gethostname()
            local_ips = [socket.gethostbyname(hostname)]
            try:
                # Add all interface IPs on Linux
                import subprocess
                res = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
                local_ips.extend(res.stdout.split())
            except Exception:
                pass
            unique_ips = sorted(list(set(local_ips)))
            print_and_discord(f"Starting SFTP server (asyncssh {asyncssh.__version__}) on {host}:{port}...", webhook_url)
            print_and_discord(f"Detected VM IPs: {', '.join(unique_ips)}", webhook_url)
            if serve_global_flat:
                print_and_discord("SFTP root mode: virtual flattened root over all input/output paths", webhook_url)
            if serve_root_path:
                print_and_discord(f"SFTP root mode: physical path {serve_root_path}", webhook_url)
            server_host_keys = []
            if host_key_path and os.path.exists(host_key_path):
                server_host_keys = [host_key_path]
            else:
                try:
                    ed25519_key = asyncssh.generate_private_key('ssh-ed25519')
                    server_host_keys.append(ed25519_key)
                except Exception as e:
                    print_and_discord(f"Warning: could not generate Ed25519 key: {e}", webhook_url)
                try:
                    rsa_key = asyncssh.generate_private_key('ssh-rsa')
                    server_host_keys.append(rsa_key)
                except Exception as e:
                    print_and_discord(f"Warning: could not generate RSA key: {e}", webhook_url)

            if not server_host_keys:
                server_host_keys = None

            server = await asyncssh.listen(
                host,
                port,
                server_factory=lambda: SimpleSSHServer(username_cfg, password_cfg, webhook_url),
                server_host_keys=server_host_keys,
                sftp_factory=lambda chan: SimpleSFTPServer(
                    chan,
                    upload_src_path,
                    serve_root_path=serve_root_path,
                    serve_root_flat=serve_root_flat,
                    serve_global_flat=serve_global_flat,
                ),
            )

            actual_host, actual_port = server.sockets[0].getsockname()[:2]
            print_and_discord(f"SUCCESS: SFTP server is READY and listening on {actual_host}:{actual_port}", webhook_url)
            if host == '127.0.0.1':
                print_and_discord("CRITICAL WARNING: SFTP server is bound ONLY to 127.0.0.1.", webhook_url)
                print_and_discord("Connections from OUTSIDE the VM (including VirtualBox port forwarding) will fail.", webhook_url)
                print_and_discord("Please set 'host: 0.0.0.0' in config.yml to allow external connections.", webhook_url)
            await server.wait_closed()
        except Exception as e:
            print_and_discord(f"SFTP server error during startup or execution: {e}", webhook_url)

    def run_server():
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(start_server())
        except Exception as e:
            print_and_discord(f"Could not start SFTP server: {e}", webhook_url)

    threading.Thread(target=run_server, daemon=True).start()

def create_virtual_fuse_class():
    class VirtualFUSE(Operations):
        def __init__(self, upload_src_path):
            self.upload_src_path = upload_src_path
            os.makedirs(self.upload_src_path, exist_ok=True)

        def _upload_physical_path(self, path):
            rel = path.lstrip('/')
            return os.path.join(self.upload_src_path, rel) if rel else self.upload_src_path

        def getattr(self, path, fh=None):
            is_file, is_dir, physical_path = get_virtual_item_info(path)
            if physical_path and os.path.exists(physical_path):
                st = os.lstat(physical_path)
                return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                             'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))
            if is_dir:
                mode = stat.S_IFDIR | 0o755
                now = time.time()
                return {
                    'st_atime': now, 'st_ctime': now, 'st_mtime': now,
                    'st_gid': os.getgid() if hasattr(os, 'getgid') else 0,
                    'st_uid': os.getuid() if hasattr(os, 'getuid') else 0,
                    'st_mode': mode, 'st_nlink': 2, 'st_size': 0
                }
            raise FuseOSError(errno.ENOENT)

        def readdir(self, path, fh):
            names = list_virtual_dir(path)
            dirents = ['.', '..']
            dirents.extend(names.keys())
            for r in dirents:
                yield r

        def open(self, path, flags):
            is_file, is_dir, physical_path = get_virtual_item_info(path)
            if not physical_path or not os.path.exists(physical_path):
                raise FuseOSError(errno.ENOENT)
            return os.open(physical_path, flags)

        def create(self, path, mode, fi=None):
            rel = path.lstrip('/')
            if not rel:
                raise FuseOSError(errno.EINVAL)
            physical_path = os.path.join(self.upload_src_path, rel)
            os.makedirs(os.path.dirname(physical_path), exist_ok=True)
            return os.open(physical_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)

        def read(self, path, length, offset, fh):
            os.lseek(fh, offset, os.SEEK_SET)
            return os.read(fh, length)

        def write(self, path, buf, offset, fh):
            os.lseek(fh, offset, os.SEEK_SET)
            return os.write(fh, buf)

        def truncate(self, path, length, fh=None):
            is_file, is_dir, physical_path = get_virtual_item_info(path)
            if physical_path:
                with open(physical_path, 'r+b') as f:
                    f.truncate(length)

        def flush(self, path, fh):
            return os.fsync(fh)

        def release(self, path, fh):
            return os.close(fh)

        def unlink(self, path):
            physical_path = get_physical_path_for_virtual(path)
            if physical_path and os.path.exists(physical_path):
                os.remove(physical_path)
            else:
                raise FuseOSError(errno.ENOENT)

        def mkdir(self, path, mode):
            physical_path = self._upload_physical_path(path)
            os.makedirs(physical_path, exist_ok=True)

        def rmdir(self, path):
            is_file, is_dir, physical_path = get_virtual_item_info(path)
            if not is_dir:
                raise FuseOSError(errno.ENOENT)
            if physical_path and os.path.isdir(physical_path):
                try:
                    os.rmdir(physical_path)
                    return
                except OSError as exc:
                    raise FuseOSError(exc.errno) from exc
            rel = path.lstrip('/')
            for base in get_vfs_base_paths():
                candidate = os.path.join(base, rel)
                if os.path.isdir(candidate):
                    try:
                        os.rmdir(candidate)
                        return
                    except OSError as exc:
                        raise FuseOSError(exc.errno) from exc
            raise FuseOSError(errno.ENOENT)

        def rename(self, old, new):
            is_file, is_dir, old_physical = get_virtual_item_info(old)
            if not old_physical or not os.path.exists(old_physical):
                raise FuseOSError(errno.ENOENT)
            new_physical = self._upload_physical_path(new)
            os.makedirs(os.path.dirname(new_physical), exist_ok=True)
            os.rename(old_physical, new_physical)

    return VirtualFUSE


def start_fuse_server_thread(fuse_config, upload_src_path, webhook_url):
    if not fuse_config.get('enabled', False):
        return {'enabled': False, 'failed': False, 'error': ''}
    if FUSE is None:
        print_and_discord("FUSE support is disabled because 'fusepy' is not installed or libfuse is missing.", webhook_url)
        return {'enabled': True, 'failed': True, 'error': "FUSE library not available"}

    mount_point = fuse_config.get('mount_point')
    if not mount_point:
        print_and_discord("FUSE mount point not configured.", webhook_url)
        return {'enabled': True, 'failed': True, 'error': "FUSE mount point not configured"}

    os.makedirs(mount_point, exist_ok=True)
    register_fuse_cleanup_handlers(mount_point, webhook_url, True)
    fuse_status = {'enabled': True, 'failed': False, 'error': ''}

    def run_fuse():
        try:
            print_and_discord(f"Starting FUSE mount at {mount_point}", webhook_url)
            cls = create_virtual_fuse_class()
            FUSE(cls(upload_src_path), mount_point, nothreads=True, foreground=True)
        except Exception as e:
            fuse_status['failed'] = True
            fuse_status['error'] = str(e)
            print_and_discord(f"FUSE mount failed: {e}", webhook_url)

    threading.Thread(target=run_fuse, daemon=True).start()
    return fuse_status


_fuse_cleanup_lock = threading.Lock()
_fuse_cleanup_done = False
_fuse_cleanup_mount_point = None
_fuse_cleanup_webhook_url = ''
_fuse_cleanup_remove_dir_if_empty = False
_fuse_cleanup_handlers_registered = False


def _run_command_quiet(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        return result.returncode == 0
    except Exception:
        return False


def _attempt_unmount_fuse(mount_point):
    system = sys.platform.lower()
    commands = []
    if system.startswith('win'):
        commands.extend([
            ['fusermount', '-u', mount_point],
            ['umount', mount_point],
            ['mountvol', mount_point, '/D'],
        ])
    elif system == 'darwin':
        commands.extend([
            ['umount', mount_point],
            ['diskutil', 'unmount', mount_point],
        ])
    else:
        commands.extend([
            ['fusermount', '-u', mount_point],
            ['fusermount3', '-u', mount_point],
            ['umount', mount_point],
        ])

    for command in commands:
        executable = command[0]
        if executable not in ('mountvol',) and shutil.which(executable) is None:
            continue
        if _run_command_quiet(command):
            return True
    return False


def cleanup_fuse_mount(force=False):
    global _fuse_cleanup_done
    with _fuse_cleanup_lock:
        if _fuse_cleanup_done and not force:
            return
        mount_point = _fuse_cleanup_mount_point
        webhook_url = _fuse_cleanup_webhook_url
        remove_dir_if_empty = _fuse_cleanup_remove_dir_if_empty
        if not mount_point:
            _fuse_cleanup_done = True
            return

        try:
            if os.path.exists(mount_point) and os.path.ismount(mount_point):
                _attempt_unmount_fuse(mount_point)
                deadline = time.time() + 2.0
                while time.time() < deadline and os.path.ismount(mount_point):
                    time.sleep(0.1)

            if os.path.exists(mount_point) and not os.path.ismount(mount_point) and remove_dir_if_empty:
                try:
                    os.rmdir(mount_point)
                    print_and_discord(f"FUSE mount directory removed: {mount_point}", webhook_url)
                except OSError:
                    pass
        except Exception as e:
            print_and_discord(f"FUSE cleanup warning: {e}", webhook_url)
        finally:
            _fuse_cleanup_done = True


def register_fuse_cleanup_handlers(mount_point, webhook_url, remove_dir_if_empty):
    global _fuse_cleanup_mount_point, _fuse_cleanup_webhook_url
    global _fuse_cleanup_remove_dir_if_empty, _fuse_cleanup_handlers_registered
    global _fuse_cleanup_done
    _fuse_cleanup_mount_point = mount_point
    _fuse_cleanup_webhook_url = webhook_url
    _fuse_cleanup_remove_dir_if_empty = remove_dir_if_empty
    _fuse_cleanup_done = False
    if _fuse_cleanup_handlers_registered:
        return

    def _cleanup_signal_handler(signum, frame):
        cleanup_fuse_mount()
        raise SystemExit(0)

    atexit.register(cleanup_fuse_mount)
    for signal_name in ('SIGINT', 'SIGTERM', 'SIGBREAK'):
        sig = getattr(signal, signal_name, None)
        if sig is not None:
            signal.signal(sig, _cleanup_signal_handler)
    _fuse_cleanup_handlers_registered = True

def get_last_modified_time(path):
    last_modified_timestamp = os.path.getmtime(path)
    last_modified_date = datetime.fromtimestamp(last_modified_timestamp)
    return last_modified_date

def get_file_size(path):
    return os.path.getsize(path)

def has_sufficient_free_space(disk, required_gb):
    total, used, free = shutil.disk_usage(disk)
    free_gb = free // (2**30)
    return free_gb >= required_gb

def save_config_if_missing(config_data, config_path=config_path):
    if os.path.exists(config_path):
        return

    src = config_data.get('src', '')
    webhook_url = config_data.get('webhook_url', '')
    disks = config_data.get('disks', [])
    last_disk = config_data.get('last_disk', '')
    settings = config_data.get('settings', {})
    space_hunter_disks = config_data.get('space_hunter_disks', [])
    reverse_raid_config = config_data.get('reverse_raid') or {}
    webdav_server_config = config_data.get('webdav_server') or {}
    sftp_server_config = config_data.get('sftp_server') or {}
    fuse_server_config = config_data.get('fuse_server') or {}

    min_file_age_hours = settings.get('min_file_age_hours', 4)
    extra_safety_space_gb = settings.get('extra_safety_space_gb', 5)
    scan_interval_seconds = settings.get('scan_interval_seconds', 120)
    console_clear_interval_hours = settings.get('console_clear_interval_hours', 6)
    space_check_default_min_free_gb = settings.get('space_check_default_min_free_gb', 40)

    webdav_enabled = webdav_server_config.get('enabled', False)
    webdav_host = webdav_server_config.get('host', '0.0.0.0')
    webdav_port = webdav_server_config.get('port', 8080)
    webdav_username = webdav_server_config.get('username', 'admin')
    webdav_password = webdav_server_config.get('password', 'admin')
    webdav_upload_src = webdav_server_config.get('upload_src', src)
    webdav_use_fuse = webdav_server_config.get('use_fuse_mount_as_root', True)

    sftp_enabled = sftp_server_config.get('enabled', False)
    sftp_host = sftp_server_config.get('host', '0.0.0.0')
    sftp_port = sftp_server_config.get('port', 2222)
    sftp_username = sftp_server_config.get('username', 'raiduser')
    sftp_password = sftp_server_config.get('password', 'changeme')
    sftp_upload_src = sftp_server_config.get('upload_src', src)
    sftp_use_fuse = sftp_server_config.get('use_fuse_mount_as_root', True)

    fuse_enabled = fuse_server_config.get('enabled', False)
    fuse_mount_point = fuse_server_config.get('mount_point', os.path.join(current_dir, 'mount'))
    fuse_upload_src = fuse_server_config.get('upload_src', src)

    lines = []
    lines.append("######################################################################")
    lines.append("# VulcanoCraft MultiDisk FileBalancer - configuration file")
    lines.append("#")
    lines.append("# This file contains everything the program needs to run.")
    lines.append("# The goal is that you do NOT need to change the code itself.")
    lines.append("#")
    lines.append("# Important:")
    lines.append("# - Everything starting with # is a comment and ignored by the program.")
    lines.append("# - Only change the values AFTER the : character.")
    lines.append("# - Always use absolute paths (for example C:\\Games\\Worlds\\Map1).")
    lines.append("######################################################################")
    lines.append("")
    lines.append("######################################################################")
    lines.append("# GENERAL SETTINGS")
    lines.append("######################################################################")
    lines.append("")
    lines.append("# src:")
    lines.append("# This is the folder where new files arrive.")
    lines.append("# Example: an \"input\" folder where your download/recording/backup files")
    lines.append("# end up. The script automatically distributes these files")
    lines.append("# over the configured disks.")
    lines.append(f"src: {src}")
    lines.append("")
    lines.append("# webhook_url:")
    lines.append("# Optional: a Discord webhook URL for notifications.")
    lines.append("# - Leave empty ('') to disable Discord notifications.")
    lines.append("# - Paste your webhook URL here if you want notifications.")
    lines.append(f"webhook_url: '{webhook_url}'")
    lines.append("")
    lines.append("######################################################################")
    lines.append("# RAID-0 / FILE DISTRIBUTION SETTINGS")
    lines.append("######################################################################")
    lines.append("")
    lines.append("# disks:")
    lines.append("# List of disks/folders where files will be moved.")
    lines.append("# - name: a short recognizable name (e.g. disk1, SSD, HDD1, etc.)")
    lines.append("# - path: the folder on that disk where files should end up.")
    lines.append("# You can add as many disks here as you like.")
    lines.append("disks:")
    for disk in disks:
        name = disk.get('name', '')
        path = disk.get('path', '')
        lines.append(f"  - name: {name}")
        lines.append(f"    path: {path}")
    lines.append("")
    lines.append("# last_disk:")
    lines.append("# This is the name of the last disk that was used.")
    lines.append("# The script uses this to send the next file to the next")
    lines.append("# disk in the list (round-robin distribution).")
    lines.append("# - Normally you do NOT need to change this manually.")
    lines.append("# - If you want to force the script to start again at a specific")
    lines.append("#   disk, you can set a different name here.")
    lines.append(f"last_disk: {last_disk}")
    lines.append("")
    lines.append("######################################################################")
    lines.append("# TECHNICAL SETTINGS FOR FILE DISTRIBUTION")
    lines.append("######################################################################")
    lines.append("")
    lines.append("settings:")
    lines.append("  # min_file_age_hours:")
    lines.append("  # A file must be at least this many hours old before it is moved.")
    lines.append("  # This prevents files that are still being written (for example")
    lines.append("  # recordings or downloads) from being moved too early.")
    lines.append("  # Example:")
    lines.append("  # - 4 means: only files older than 4 hours are moved.")
    lines.append(f"  min_file_age_hours: {min_file_age_hours}")
    lines.append("")
    lines.append("  # extra_safety_space_gb:")
    lines.append("  # Extra free space (in GB) that must be available on the target disk")
    lines.append("  # on top of the file size.")
    lines.append("  # Example:")
    lines.append("  # - File size = 10 GB, extra_safety_space_gb = 5")
    lines.append("  #   Requires at least 15 GB free on the target disk.")
    lines.append(f"  extra_safety_space_gb: {extra_safety_space_gb}")
    lines.append("")
    lines.append("  # scan_interval_seconds:")
    lines.append("  # How often the script checks the source folder for new files.")
    lines.append("  # Value is in seconds.")
    lines.append("  # Example:")
    lines.append("  # - 120 means: every 2 minutes.")
    lines.append(f"  scan_interval_seconds: {scan_interval_seconds}")
    lines.append("")
    lines.append("  # console_clear_interval_hours:")
    lines.append("  # Every so many hours the console is cleared to keep things readable.")
    lines.append("  # Messages will still be sent to Discord (if configured).")
    lines.append(f"  console_clear_interval_hours: {console_clear_interval_hours}")
    lines.append("")
    lines.append("  # space_check_default_min_free_gb:")
    lines.append("  # Default minimum free space (in GB) for the \"space hunter\" feature")
    lines.append("  # when you configure it interactively in the program.")
    lines.append("  # Per disk below you can also set a custom min_free_gb.")
    lines.append(f"  space_check_default_min_free_gb: {space_check_default_min_free_gb}")
    lines.append("")
    lines.append("######################################################################")
    lines.append("# SPACE HUNTER - AUTOMATIC DISK CLEANUP")
    lines.append("######################################################################")
    lines.append("#")
    lines.append("# With \"space_hunter_disks\" you can configure disks which are")
    lines.append("# automatically cleaned up when free space becomes too low.")
    lines.append("#")
    lines.append("# For each disk you can configure:")
    lines.append("# - path:            The folder on the disk that is monitored.")
    lines.append("# - min_free_gb:     Minimum free space in GB you want to keep.")
    lines.append("# - action:          What happens when free space drops BELOW the limit:")
    lines.append("#                      * 'delete'  -> oldest file is permanently deleted")
    lines.append("#                      * 'move'    -> oldest file is moved")
    lines.append("# - move_destination:")
    lines.append("#                    Only needed when action = 'move'.")
    lines.append("#                    This is the folder where the oldest file is moved to.")
    lines.append("#")
    lines.append("# Note:")
    lines.append("# - The \"oldest\" file is determined by the last modified timestamp.")
    lines.append("# - Use this only on folders where it is safe to delete or move")
    lines.append("#   old files.")
    lines.append("space_hunter_disks:")
    if space_hunter_disks:
        for disk in space_hunter_disks:
            action = disk.get('action', 'delete')
            min_free_gb = disk.get('min_free_gb', space_check_default_min_free_gb)
            path = disk.get('path', '')
            move_destination = disk.get('move_destination')
            move_value = "null" if not move_destination else move_destination
            lines.append(f"  - action: {action}")
            lines.append(f"    min_free_gb: {min_free_gb}")
            lines.append(f"    path: {path}")
            lines.append(f"    move_destination: {move_value}")
            lines.append("")
    else:
        lines.append("  # Example:")
        lines.append("  # - action: delete")
        lines.append("  #   min_free_gb: 40")
        lines.append("  #   path: C:\\Example\\Path")
        lines.append("  #   move_destination: null")
        lines.append("")
    lines.append("######################################################################")
    lines.append("# REVERSE RAID 0 SIMULATOR - MERGE FILES BACK")
    lines.append("######################################################################")
    lines.append("#")
    lines.append("# With \"reverse_raid\" you can collect files that are spread across")
    lines.append("# multiple folders/disks back into a single central folder.")
    lines.append("# This works similarly to the separate reverse_raid program, but is")
    lines.append("# now integrated into this script and controlled entirely via this config.")
    lines.append("#")
    lines.append("# Typical use case:")
    lines.append("# - You have multiple target folders where the FileBalancer has placed")
    lines.append("#   files.")
    lines.append("# - You want to later move older files back into one folder (for example")
    lines.append("#   for a backup, archive or to free up space on the target disks).")
    lines.append("#")
    lines.append("# Note:")
    lines.append("# - Files are only moved if they are older than the configured")
    lines.append("#   min_file_age_hours value.")
    lines.append("# - If a file with the same name already exists in the destination")
    lines.append("#   folder, the file is skipped.")

    reverse_enabled = reverse_raid_config.get('enabled', False)
    reverse_source_paths = reverse_raid_config.get('source_paths', [])
    reverse_destination_path = reverse_raid_config.get('destination_path', src)
    reverse_min_age_hours = reverse_raid_config.get('min_file_age_hours', 12)
    reverse_interval_minutes = reverse_raid_config.get('run_interval_minutes', 10)

    lines.append("reverse_raid:")
    lines.append("  # enabled:")
    lines.append("  # - true  = reverse RAID feature is active")
    lines.append("  # - false = reverse RAID feature is disabled")
    lines.append(f"  enabled: {'true' if reverse_enabled else 'false'}")
    lines.append("")
    lines.append("  # source_paths:")
    lines.append("  # List of folders where the files CURRENTLY live (for example your")
    lines.append("  # target1/target2/target3 folders). The script will try to move")
    lines.append("  # files from these folders back to the destination.")
    lines.append("  source_paths:")
    if reverse_source_paths:
        for path in reverse_source_paths:
            lines.append(f"    - {path}")
    else:
        for disk in disks:
            path = disk.get('path', '')
            if path:
                lines.append(f"    - {path}")
    lines.append("")
    lines.append("  # destination_path:")
    lines.append("  # The folder where files are moved TO. This is often")
    lines.append("  # your original source folder or a separate \"collection\" folder.")
    lines.append(f"  destination_path: {reverse_destination_path}")
    lines.append("")
    lines.append("  # min_file_age_hours:")
    lines.append("  # Only files at least this many hours old are moved.")
    lines.append("  # This prevents recently moved or still active files from being")
    lines.append("  # shuffled back and forth.")
    lines.append(f"  min_file_age_hours: {reverse_min_age_hours}")
    lines.append("")
    lines.append("  # run_interval_minutes:")
    lines.append("  # How often the reverse RAID check runs.")
    lines.append("  # - 10 means: roughly every 10 minutes it checks if files")
    lines.append("  #   can be moved from source_paths to destination_path.")
    lines.append(f"  run_interval_minutes: {reverse_interval_minutes}")

    lines.append("")
    lines.append("######################################################################")
    lines.append("# WEBDAV SERVER FOR VIRTUAL DISK")
    lines.append("######################################################################")
    lines.append("#")
    lines.append("# With \"webdav_server\" you can enable a WebDAV server so that you can")
    lines.append("# mount this system as a network drive in Windows/macOS/Linux.")
    lines.append("#")
    lines.append("# Authentication:")
    lines.append("# - username: username for WebDAV access.")
    lines.append("# - password: password for WebDAV access.")
    lines.append("#")
    lines.append("# Files uploaded via this server are stored in the upload_src folder.")
    lines.append("webdav_server:")
    lines.append(f"  enabled: {'true' if webdav_enabled else 'false'}")
    lines.append(f"  host: {webdav_host}")
    lines.append(f"  port: {webdav_port}")
    lines.append(f"  username: '{webdav_username}'")
    lines.append(f"  password: '{webdav_password}'")
    lines.append(f"  upload_src: {webdav_upload_src}")
    lines.append(f"  use_fuse_mount_as_root: {'true' if webdav_use_fuse else 'false'}")

    lines.append("")
    lines.append("######################################################################")
    lines.append("# SFTP SERVER FOR VIRTUAL DISK")
    lines.append("######################################################################")
    lines.append("#")
    lines.append("# With \"sftp_server\" you can enable an SFTP server so that you can")
    lines.append("# connect with a normal SFTP client (for example WinSCP, FileZilla,")
    lines.append("# Cyberduck, etc.) as if this system is one large disk.")
    lines.append("#")
    lines.append("# Important points:")
    lines.append("# - Only username + password authentication is used.")
    lines.append("#   You do not need to create or manage SSH keys.")
    lines.append("# - The folder you configure as upload_src below becomes the \"root\"")
    lines.append("#   you see in your SFTP client. Everything you put there is picked up")
    lines.append("#   by the FileBalancer as input (just like the normal src folders).")
    lines.append("# - The actual distribution across the disks is then handled by the")
    lines.append("#   existing logic of the script.")
    lines.append("# - use_fuse_mount_as_root: if true (and fuse_server is enabled),")
    lines.append("#   the server will show the same \"flattened\" view as the FUSE mount.")
    lines.append("sftp_server:")
    lines.append(f"  enabled: {'true' if sftp_enabled else 'false'}")
    lines.append(f"  host: {sftp_host}")
    lines.append(f"  port: {sftp_port}")
    lines.append(f"  username: '{sftp_username}'")
    lines.append(f"  password: '{sftp_password}'")
    lines.append(f"  upload_src: {sftp_upload_src}")
    lines.append(f"  use_fuse_mount_as_root: {'true' if sftp_use_fuse else 'false'}")

    lines.append("")
    lines.append("######################################################################")
    lines.append("# FUSE SERVER FOR VIRTUAL DISK")
    lines.append("######################################################################")
    lines.append("#")
    lines.append("# With \"fuse_server\" you can mount the virtual disk locally on your")
    lines.append("# machine. This allows you to access all files across all disks as")
    lines.append("# if they are in one single folder.")
    lines.append("#")
    lines.append("# Important points:")
    lines.append("# - This requires 'libfuse' to be installed on your system.")
    lines.append("# - The mount_point is the local folder where the virtual disk")
    lines.append("#   will be attached.")
    lines.append("# - Everything you put into the mount point will be picked up")
    lines.append("#   by the FileBalancer (via the upload_src folder).")
    lines.append("fuse_server:")
    lines.append(f"  enabled: {'true' if fuse_enabled else 'false'}")
    lines.append(f"  mount_point: {fuse_mount_point}")
    lines.append(f"  upload_src: {fuse_upload_src}")

    with open(config_path, 'w', encoding='utf-8') as config_file:
        config_file.write("\n".join(lines) + "\n")

def read_config(config_path=config_path):
    if os.path.exists(config_path):
        with open(config_path, 'r') as yaml_file:
            config_data = yaml.safe_load(yaml_file)
            print(f"Config loaded from: {os.path.abspath(config_path)}")
            print(f"Config data: {config_data}")
            return config_data
    return None

def send_discord_message(message, webhook_url):
    if not webhook_url:
        return
    try:
        data = {
            "content": message
        }
        requests.post(webhook_url, json=data)
    except Exception as e:
        print(f"Error sending Discord message: {e}")

def print_and_discord(message, webhook_url):
    print(message)
    sys.stdout.flush()
    send_discord_message(message, webhook_url)

def get_next_disk(current_disk, disks):
    current_index = disks.index(current_disk)
    next_index = (current_index + 1) % len(disks)
    return disks[next_index]

def ask_disk_info(disk_number):
    path = input(f"Enter the path for disk {disk_number}: ")
    name = f"disk{disk_number}"
    return {
        'path': path,
        'name': name
    }

def check_files_and_move(src, disks, last_disk, webhook_url, min_file_age_hours, extra_safety_space_gb):
    new_last_disk = last_disk
    time_limit = timedelta(hours=min_file_age_hours)
    now = datetime.now()

    files_to_move = []
    for dirpath, _dirnames, filenames in os.walk(src):
        for filename in filenames:
            source_path = os.path.join(dirpath, filename)
            modified_date = get_last_modified_time(source_path)
            if now - modified_date > time_limit:
                rel_path = os.path.relpath(source_path, src)
                files_to_move.append(rel_path)
            else:
                print_and_discord(f"{filename} was modified too recently and will not be moved.", webhook_url)

    if not files_to_move:
        print_and_discord("\nFile moving completed!", webhook_url)
        return new_last_disk

    print_and_discord("\nStarting to move files:", webhook_url)
    disk_names = [disk['name'] for disk in disks]
    disks_by_name = {disk['name']: disk for disk in disks}
    disk_locks = {disk_name: threading.Lock() for disk_name in disk_names}
    scheduling_lock = threading.Lock()
    last_disk_holder = {'name': new_last_disk if new_last_disk in disk_names else disk_names[0]}

    def pick_start_disk():
        with scheduling_lock:
            return get_next_disk(last_disk_holder['name'], disk_names)

    def update_last_disk(disk_name):
        with scheduling_lock:
            last_disk_holder['name'] = disk_name

    def move_single_file(rel_path):
        source_path = os.path.join(src, rel_path)
        if not os.path.exists(source_path):
            return None
        file_size_gb = get_file_size(source_path) // (2**30)
        required_space = file_size_gb + extra_safety_space_gb
        start_disk = pick_start_disk()
        start_index = disk_names.index(start_disk)

        for offset in range(len(disk_names)):
            target_disk = disk_names[(start_index + offset) % len(disk_names)]
            target_info = disks_by_name[target_disk]
            target_path = target_info['path']
            print_and_discord(
                f"File: {rel_path}, Size: {file_size_gb} GB, Required space: {required_space} GB",
                webhook_url,
            )
            print_and_discord(f"Attempting to move to {target_disk}", webhook_url)

            with disk_locks[target_disk]:
                if not os.path.exists(source_path):
                    return None
                if has_sufficient_free_space(target_path, required_space):
                    destination_path = os.path.join(target_path, rel_path)
                    os.makedirs(os.path.dirname(destination_path), exist_ok=True)
                    shutil.move(source_path, destination_path)
                    print_and_discord(f"{rel_path} moved to {target_disk}", webhook_url)
                    update_last_disk(target_disk)
                    return target_disk
                print_and_discord(f"Not enough space for {rel_path} on {target_disk}", webhook_url)

        print_and_discord(f"No disk has enough space for {rel_path}, skipping file.", webhook_url)
        return None

    async def run_transfers():
        max_workers = max(2, min(8, len(disk_names) * 2, len(files_to_move)))
        semaphore = asyncio.Semaphore(max_workers)

        async def transfer_file(rel_path):
            async with semaphore:
                await asyncio.to_thread(move_single_file, rel_path)

        await asyncio.gather(*(transfer_file(rel_path) for rel_path in files_to_move))

    asyncio.run(run_transfers())
    new_last_disk = last_disk_holder['name']

    print_and_discord("\nFile moving completed!", webhook_url)
    return new_last_disk

def remove_oldest_file(folder_path, webhook_url, action, move_destination=None):
    oldest_file = None
    oldest_time = float('inf')

    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path):
            last_modified = os.path.getmtime(file_path)
            if last_modified < oldest_time:
                oldest_time = last_modified
                oldest_file = file_path

    if oldest_file:
        try:
            if action == 'move' and move_destination:
                new_path = os.path.join(move_destination, os.path.basename(oldest_file))
                shutil.move(oldest_file, new_path)
                print_and_discord(f"The oldest file was moved: {oldest_file} to {new_path}", webhook_url)
            elif action == 'delete':
                os.remove(oldest_file)
                print_and_discord(f"The oldest file was deleted: {oldest_file}", webhook_url)
            else:
                print_and_discord(f"Invalid action or missing move destination: {action}", webhook_url)
        except Exception as e:
            print_and_discord(f"Error while performing action on {oldest_file}: {e}", webhook_url)
    else:
        print_and_discord("No files found in the specified folder.", webhook_url)

def check_free_space(disk_path, min_free_gb, webhook_url, action, move_destination):
    if os.name == 'nt':
        disk_path = disk_path.replace('/', '\\')

    total, used, free = shutil.disk_usage(disk_path)
    free_gb = free / (2**30)

    if free_gb < min_free_gb:
        print_and_discord(
            f"Insufficient space. Only {free_gb:.2f} GB free on {disk_path}.",
            webhook_url,
        )
        remove_oldest_file(disk_path, webhook_url, action, move_destination)
    else:
        print_and_discord(
            f"Sufficient space available. {free_gb:.2f} GB free on {disk_path}.",
            webhook_url,
        )

def check_and_cleanup_disks(space_hunter_disks, webhook_url, default_min_free_gb):
    for disk in space_hunter_disks:
        disk_path = disk.get('path')
        min_free_gb = disk.get('min_free_gb', default_min_free_gb)
        action = disk.get('action', 'delete')
        move_destination = disk.get('move_destination')
        if disk_path:
            check_free_space(disk_path, min_free_gb, webhook_url, action, move_destination)

def reverse_move_files(reverse_config, webhook_url):
    destination_path = reverse_config.get('destination_path')
    source_paths = reverse_config.get('source_paths', [])
    min_age_hours = reverse_config.get('min_file_age_hours', 12)

    if not destination_path or not source_paths:
        print_and_discord("Reverse RAID: no valid source_paths or destination_path configured.", webhook_url)
        return

    os.makedirs(destination_path, exist_ok=True)

    total_files = 0
    total_moved = 0
    total_skipped_too_new = 0

    print_and_discord(
        f"Reverse RAID: start moving files (older than {min_age_hours} hours).",
        webhook_url,
    )

    for index, source_folder in enumerate(source_paths):
        if not source_folder:
            continue
        if not os.path.isdir(source_folder):
            print_and_discord(
                f"Reverse RAID: source folder {index + 1} ({source_folder}) does not exist or is not a folder.",
                webhook_url,
            )
            continue

        files_in_folder = 0
        moved_in_folder = 0

        for dirpath, _dirnames, filenames in os.walk(source_folder):
            for filename in filenames:
                source_path = os.path.join(dirpath, filename)
                rel_path = os.path.relpath(source_path, source_folder)
                destination_file_path = os.path.join(destination_path, rel_path)

                file_time = os.path.getmtime(source_path)
                file_age_hours = (time.time() - file_time) / 3600

                if file_age_hours < min_age_hours:
                    print_and_discord(
                        f"Reverse RAID: skipping {rel_path}, too new ({file_age_hours:.1f} hours).",
                        webhook_url,
                    )
                    total_skipped_too_new += 1
                    continue

                total_files += 1
                files_in_folder += 1

                if os.path.exists(destination_file_path):
                    print_and_discord(
                        f"Reverse RAID: skipping {rel_path}, already exists in destination folder.",
                        webhook_url,
                    )
                    continue

                try:
                    os.makedirs(os.path.dirname(destination_file_path), exist_ok=True)
                    shutil.move(source_path, destination_file_path)
                    print_and_discord(f"Reverse RAID: moved {rel_path}", webhook_url)
                    total_moved += 1
                    moved_in_folder += 1
                except Exception as e:
                    print_and_discord(
                        f"Reverse RAID: error while moving {rel_path}: {e}",
                        webhook_url,
                    )

        if files_in_folder > 0:
            print_and_discord(
                f"Reverse RAID: folder {index + 1}: moved {moved_in_folder} of {files_in_folder} files from {source_folder}",
                webhook_url,
            )

    if total_moved > 0 or total_files > 0:
        print_and_discord(
            f"Reverse RAID: finished, moved {total_moved} of {total_files} files to {destination_path}",
            webhook_url,
        )
    else:
        print_and_discord("Reverse RAID: no files moved in this cycle.", webhook_url)

def main():
    config = read_config() or {}
    config_exists = os.path.exists(config_path)

    settings = config.get('settings', {})
    min_file_age_hours = settings.get('min_file_age_hours', 4)
    extra_safety_space_gb = settings.get('extra_safety_space_gb', 5)
    scan_interval_seconds = settings.get('scan_interval_seconds', 120)
    console_clear_interval_hours = settings.get('console_clear_interval_hours', 6)
    space_check_default_min_free_gb = settings.get('settings', {}).get('space_check_default_min_free_gb', 40)

    reverse_raid_config = config.get('reverse_raid', {})
    reverse_enabled = reverse_raid_config.get('enabled', False)
    reverse_interval_minutes = reverse_raid_config.get('run_interval_minutes', 10)

    webdav_server_config = config.get('webdav_server', {})
    sftp_server_config = config.get('sftp_server', {})
    fuse_server_config = config.get('fuse_server', {})

    print("Config loaded from config.yml (or default values used when missing):")

    src_folders_config = config.get('src_folders')
    src_from_config = config.get('src', '')
    src_folders = []

    if src_folders_config:
        src_folders = [path for path in src_folders_config if path]
    elif config_exists and src_from_config:
        src_folders = [src_from_config]
    else:
        try:
            num_input_folders = int(input("How many input folders do you want to configure? "))
        except ValueError:
            num_input_folders = 1
        if num_input_folders < 1:
            num_input_folders = 1
        for i in range(num_input_folders):
            if i == 0 and src_from_config:
                src_path = src_from_config
            else:
                src_path = input(f"Enter the path for input folder {i + 1}: ")
            src_folders.append(src_path)

    if not src_folders:
        if config_exists and src_from_config:
            src_folders = [src_from_config]
        else:
            src_path = input("Enter the path for the input folder: ")
            src_folders = [src_path]

    extra_input_folders = []
    for key in ('input_folders', 'inputs', 'source_folders'):
        value = config.get(key)
        if isinstance(value, list):
            extra_input_folders.extend(path for path in value if path)
    for extra_input in extra_input_folders:
        if extra_input not in src_folders:
            src_folders.append(extra_input)

    extra_output_folders = []
    for key in ('output_folders', 'target_folders', 'dst_folders', 'destination_folders'):
        value = config.get(key)
        if isinstance(value, list):
            extra_output_folders.extend(path for path in value if path)

    src = src_folders[0]
    webhook_url = config.get('webhook_url', '')
    if not config_exists:
        webhook_input = input("Enter the Discord webhook URL (leave empty to disable Discord notifications): ")
        webhook_url = webhook_input if webhook_input.strip() else ""
    elif webhook_url is None:
        webhook_input = input("Enter the Discord webhook URL (leave empty to disable Discord notifications): ")
        webhook_url = webhook_input if webhook_input.strip() else ""

    disks = config.get('disks', [])
    last_disk = config.get('last_disk', '')
    space_hunter_disks = config.get('space_hunter_disks', [])

    if not disks:
        num_disks = int(input("How many disks do you want to add? "))
        disks = [ask_disk_info(i + 1) for i in range(num_disks)]
        last_disk = disks[0]['name']

    if not last_disk and disks:
        last_disk = disks[0]['name']

    if not space_hunter_disks and not config_exists:
        use_space_hunter = input("Do you want to enable automatic disk space checks and cleanup? (yes/no): ").lower() == 'yes'
        if use_space_hunter:
            min_space_input = input(f"Default minimum free space in GB for space hunter (default {space_check_default_min_free_gb}): ").strip()
            if min_space_input.isdigit():
                space_check_default_min_free_gb = int(min_space_input)
            try:
                num_cleanup_disks = int(input("How many disks do you want to monitor for free space? "))
                for i in range(num_cleanup_disks):
                    disk_path = input(f"Enter the path of disk {i + 1} to monitor: ")
                    min_free_gb_input = input(f"Enter the minimum free space in GB (default {space_check_default_min_free_gb}): ")
                    min_free_gb = int(min_free_gb_input) if min_free_gb_input.strip().isdigit() else space_check_default_min_free_gb
                    action_input = input("Enter the action (move/delete, default delete): ").lower()
                    if action_input not in ['move', 'delete']:
                        action_input = 'delete'
                    move_destination = None
                    if action_input == 'move':
                        move_destination = input("Enter the move destination path: ")
                        while not os.path.isdir(move_destination):
                            print("Invalid path. Make sure the folder exists.")
                            move_destination = input("Enter the move destination path: ")
                    space_hunter_disks.append({
                        'path': disk_path,
                        'min_free_gb': min_free_gb,
                        'action': action_input,
                        'move_destination': move_destination,
                    })
            except ValueError:
                print("Enter a valid number for the number of disks.")

    if not os.path.exists(config_path):
        print("\nAdvanced settings for file distribution:")
        min_age_input = input(f"Minimum file age in hours (default {min_file_age_hours}): ").strip()
        if min_age_input.isdigit():
            min_file_age_hours = int(min_age_input)
        extra_safety_input = input(f"Extra safety space in GB (default {extra_safety_space_gb}): ").strip()
        if extra_safety_input.isdigit():
            extra_safety_space_gb = int(extra_safety_input)
        scan_interval_input = input(f"Scan interval in seconds (default {scan_interval_seconds}): ").strip()
        if scan_interval_input.isdigit():
            scan_interval_seconds = int(scan_interval_input)
        clear_interval_input = input(f"Console clear interval in hours (default {console_clear_interval_hours}): ").strip()
        if clear_interval_input.isdigit():
            console_clear_interval_hours = int(clear_interval_input)

        shared_upload_src_input = input(f"Shared upload folder for WebDAV/SFTP/FUSE (default {src}): ").strip()
        shared_upload_src = shared_upload_src_input or src

        webdav_server_cfg = {}
        print("\nWebDAV server:")
        print("- Allows you to mount the virtual disk as a network drive.")
        print("- Requires 'wsgidav' and 'cheroot' to be installed.")
        use_webdav = input("Do you want to enable the WebDAV server? (yes/no): ").strip().lower() == 'yes'
        if use_webdav:
            default_webdav_host = webdav_server_config.get('host', '0.0.0.0')
            default_webdav_port = webdav_server_config.get('port', 8080)
            default_webdav_username = webdav_server_config.get('username', 'admin')
            default_webdav_password = webdav_server_config.get('password', 'admin')
            host_input = input(f"WebDAV host (default {default_webdav_host}): ").strip()
            port_input = input(f"WebDAV port (default {default_webdav_port}): ").strip()
            username_input = input(f"WebDAV username (default {default_webdav_username}): ").strip()
            password_input = input(f"WebDAV password (default {default_webdav_password}): ").strip()
            use_fuse_input = input("Use FUSE mount as WebDAV root for flattened view? (yes/no, default yes): ").strip().lower() != 'no'
            webdav_server_cfg = {
                'enabled': True,
                'host': host_input or default_webdav_host,
                'port': int(port_input) if port_input.isdigit() else default_webdav_port,
                'username': username_input or default_webdav_username,
                'password': password_input or default_webdav_password,
                'upload_src': shared_upload_src,
                'use_fuse_mount_as_root': use_fuse_input,
            }
        else:
            webdav_server_cfg = webdav_server_config or {
                'enabled': False,
                'host': '0.0.0.0',
                'port': 8080,
                'username': 'admin',
                'password': 'admin',
                'upload_src': src,
                'use_fuse_mount_as_root': True,
            }

        sftp_server_cfg = {}
        print("\nSFTP server:")
        print("- Allows you to connect with an SFTP client as if it is a single disk.")
        print("- Uses only username and password (no SSH keys required).")
        print("- The root folder you see in your SFTP client is the configured upload folder.")
        use_sftp = input("Do you want to enable the SFTP server? (yes/no): ").strip().lower() == 'yes'
        if use_sftp:
            default_sftp_host = sftp_server_config.get('host', '0.0.0.0')
            default_sftp_port = sftp_server_config.get('port', 2222)
            default_sftp_username = sftp_server_config.get('username', 'raiduser')
            default_sftp_password = sftp_server_config.get('password', 'changeme')
            host_input = input(f"SFTP host (default {default_sftp_host}): ").strip()
            port_input = input(f"SFTP port (default {default_sftp_port}): ").strip()
            username_input = input(f"SFTP username (default {default_sftp_username}): ").strip()
            password_input = input(f"SFTP password (default {default_sftp_password}): ").strip()
            use_fuse_input_sftp = input("Use FUSE mount as SFTP root for flattened view? (yes/no, default yes): ").strip().lower() != 'no'
            sftp_server_cfg = {
                'enabled': True,
                'host': host_input or default_sftp_host,
                'port': int(port_input) if port_input.isdigit() else default_sftp_port,
                'username': username_input or default_sftp_username,
                'password': password_input or default_sftp_password,
                'upload_src': shared_upload_src,
                'use_fuse_mount_as_root': use_fuse_input_sftp,
            }
        else:
            sftp_server_cfg = sftp_server_config or {
                'enabled': False,
                'host': '0.0.0.0',
                'port': 2222,
                'username': 'raiduser',
                'password': 'changeme',
                'upload_src': src,
                'use_fuse_mount_as_root': True,
            }

        fuse_server_cfg = {}
        print("\nFUSE local mount:")
        print("- Allows you to mount the virtual disk locally.")
        print("- Requires libfuse and 'fusepy' to be installed.")
        if FUSE is None:
            print("- Currently NOT detected. If enabled, an automatic installation attempt will be made.")

        use_fuse = input("Do you want to enable the FUSE local mount? (yes/no): ").strip().lower() == 'yes'

        if use_fuse:
            default_fuse_mount = fuse_server_config.get('mount_point', os.path.join(current_dir, 'mount'))
            mount_input = input(f"FUSE mount point (default {default_fuse_mount}): ").strip()
            fuse_server_cfg = {
                'enabled': True,
                'mount_point': mount_input or default_fuse_mount,
                'upload_src': shared_upload_src,
            }
        else:
            fuse_server_cfg = fuse_server_config or {
                'enabled': False,
                'mount_point': os.path.join(current_dir, 'mount'),
                'upload_src': src,
            }

        print("\nReverse RAID configuration:")
        use_reverse = len(src_folders) > 1
        if use_reverse:
            print(f"Reverse RAID will be enabled because you configured {len(src_folders)} input folders.")
        else:
            print("Reverse RAID will not be enabled because you configured only one input folder.")

        reverse_source_paths = []
        reverse_destination_path = src
        reverse_minimum_age_hours = 12
        reverse_interval_minutes = 10
        if use_reverse:
            reverse_source_paths = [disk['path'] for disk in disks if disk.get('path')]
            if not reverse_source_paths:
                reverse_source_paths = [folder for folder in src_folders[1:] if folder]
            print(f"Reverse RAID source folders automatically set ({len(reverse_source_paths)}): {reverse_source_paths}")
            dest_input = input(f"Enter the destination folder for reverse RAID (default {src}): ").strip()
            if dest_input:
                reverse_destination_path = dest_input
            min_age_input_rev = input(f"Minimum file age in hours for reverse RAID (default {reverse_minimum_age_hours}): ").strip()
            if min_age_input_rev.isdigit():
                reverse_minimum_age_hours = int(min_age_input_rev)
            interval_input_rev = input(f"Run interval in minutes for reverse RAID (default {reverse_interval_minutes}): ").strip()
            if interval_input_rev.isdigit():
                reverse_interval_minutes = int(interval_input_rev)

        reverse_raid_config = {
            'enabled': use_reverse,
            'source_paths': reverse_source_paths,
            'destination_path': reverse_destination_path,
            'min_file_age_hours': reverse_minimum_age_hours,
            'run_interval_minutes': reverse_interval_minutes,
        }
        reverse_enabled = use_reverse
        reverse_interval_minutes = reverse_raid_config['run_interval_minutes']

        new_config = {
            'src_folders': src_folders,
            'src': src,
            'webhook_url': webhook_url,
            'disks': disks,
            'last_disk': last_disk,
            'space_hunter_disks': space_hunter_disks,
            'settings': {
                'min_file_age_hours': min_file_age_hours,
                'extra_safety_space_gb': extra_safety_space_gb,
                'scan_interval_seconds': scan_interval_seconds,
                'console_clear_interval_hours': console_clear_interval_hours,
                'space_check_default_min_free_gb': space_check_default_min_free_gb,
            },
            'webdav_server': webdav_server_cfg,
            'sftp_server': sftp_server_cfg,
            'fuse_server': fuse_server_cfg,
        }
        if reverse_raid_config:
            new_config['reverse_raid'] = reverse_raid_config
        save_config_if_missing(new_config, config_path=config_path)
        
        # Update server configs from the newly created config
        webdav_server_config = new_config.get('webdav_server', {})
        sftp_server_config = new_config.get('sftp_server', {})
        fuse_server_config = new_config.get('fuse_server', {})

    # Normalize disks: ensure every disk has both Dutch ('naam', 'pad') and English ('name', 'path') keys.
    for disk in disks:
        if 'name' not in disk and 'naam' in disk:
            disk['name'] = disk['naam']
        if 'naam' not in disk and 'name' in disk:
            disk['naam'] = disk['name']
        if 'path' not in disk and 'pad' in disk:
            disk['path'] = disk['pad']
        if 'pad' not in disk and 'path' in disk:
            disk['pad'] = disk['path']

    # Normalize space_hunter_disks: it uses 'path'/'pad' too.
    for disk in space_hunter_disks:
        if 'path' not in disk and 'pad' in disk:
            disk['path'] = disk['pad']
        if 'pad' not in disk and 'path' in disk:
            disk['pad'] = disk['path']

    webdav_enabled = webdav_server_config.get('enabled', False)
    webdav_upload_src = webdav_server_config.get('upload_src', src)
    if webdav_enabled and webdav_upload_src and webdav_upload_src not in src_folders:
        src_folders.append(webdav_upload_src)

    fuse_enabled = fuse_server_config.get('enabled', False)
    fuse_mount_point = fuse_server_config.get('mount_point', os.path.join(current_dir, 'mount'))
    preflight_sftp_enabled = sftp_server_config.get('enabled', False)
    print_startup_preflight(
        webhook_url,
        fuse_enabled=fuse_enabled,
        webdav_enabled=webdav_enabled,
        sftp_enabled=preflight_sftp_enabled,
        fuse_mount_point=fuse_mount_point,
    )
    if fuse_enabled and FUSE is None:
        print_and_discord("FUSE support requested but libfuse is missing. Attempting automatic installation...", webhook_url)
        install_ok, install_error, needs_admin = install_libfuse()
        if install_ok:
            print_and_discord("FUSE support installed successfully!", webhook_url)
        else:
            if needs_admin:
                print_and_discord(f"Automatic FUSE installation failed due to missing privileges. {admin_restart_instruction()}", webhook_url)
            else:
                print_and_discord(f"Automatic FUSE installation failed: {install_error}", webhook_url)
            raise RuntimeError("FUSE is enabled but installation failed. Cannot continue.")
    if fuse_enabled and FUSE is None:
        raise RuntimeError("FUSE is enabled but not available on this system. Cannot continue.")

    fuse_upload_src = fuse_server_config.get('upload_src', src)
    if fuse_enabled and fuse_upload_src and fuse_upload_src not in src_folders:
        src_folders.append(fuse_upload_src)

    sftp_enabled = sftp_server_config.get('enabled', False)
    sftp_upload_src = sftp_server_config.get('upload_src', src)
    if sftp_enabled and sftp_upload_src and sftp_upload_src not in src_folders:
        src_folders.append(sftp_upload_src)

    extra_vfs_paths = list(extra_output_folders)
    reverse_source_paths = reverse_raid_config.get('source_paths', [])
    if isinstance(reverse_source_paths, list):
        extra_vfs_paths.extend(path for path in reverse_source_paths if path)
    reverse_destination_path = reverse_raid_config.get('destination_path')
    if reverse_destination_path:
        extra_vfs_paths.append(reverse_destination_path)
    for upload_path in (webdav_upload_src, sftp_upload_src, fuse_upload_src):
        if upload_path:
            extra_vfs_paths.append(upload_path)
    extra_vfs_paths = _normalized_existing_path_entries(extra_vfs_paths)

    initial_vfs_paths = build_vfs_base_paths(src_folders, disks, extra_vfs_paths)
    set_vfs_base_paths(initial_vfs_paths)

    fuse_start_status = start_fuse_server_thread(fuse_server_config, fuse_upload_src, webhook_url)

    if fuse_enabled:
        time.sleep(2)
        if fuse_start_status and fuse_start_status.get('failed'):
            fuse_error = fuse_start_status.get('error', 'Unknown FUSE startup error')
            if is_privilege_error_text(fuse_error) and not has_admin_privileges():
                print_and_discord(f"FUSE startup failed due to missing privileges. {admin_restart_instruction()}", webhook_url)
            else:
                print_and_discord(f"FUSE startup failed: {fuse_error}", webhook_url)
            raise RuntimeError("FUSE is enabled but could not start. Cannot continue.")

    webdav_serve_root_path = None
    if webdav_enabled and fuse_enabled and webdav_server_config.get('use_fuse_mount_as_root', True):
        webdav_serve_root_path = fuse_server_config.get('mount_point')

    start_webdav_server_thread(webdav_server_config, webdav_upload_src, webhook_url, serve_root_path=webdav_serve_root_path)

    sftp_serve_root_path = None
    sftp_serve_root_flat = False
    sftp_serve_global_flat = False
    if sftp_enabled and sftp_server_config.get('use_fuse_mount_as_root', True):
        sftp_serve_root_flat = True
        sftp_serve_global_flat = True

    start_sftp_server_thread(
        sftp_server_config,
        sftp_upload_src,
        webhook_url,
        serve_root_path=sftp_serve_root_path,
        serve_root_flat=sftp_serve_root_flat,
        serve_global_flat=sftp_serve_global_flat,
    )

    while True:
        all_vfs_paths = build_vfs_base_paths(src_folders, disks, extra_vfs_paths)
        set_vfs_base_paths(all_vfs_paths)
        try:
            valid_src_folders = []
            for source_folder in src_folders:
                if os.path.exists(source_folder):
                    valid_src_folders.append(source_folder)
                else:
                    print_and_discord(f"The source folder {source_folder} does not exist.", webhook_url)

            if not valid_src_folders:
                print_and_discord("No valid input folders found. Check the paths in config.yml or at startup.", webhook_url)
                input("Press Enter to try again...")
                continue

            for disk in disks:
                disk_path = disk['path']
                if not os.path.exists(disk_path):
                    print_and_discord(f"The folder {disk_path} does not exist. Creating the folder.", webhook_url)
                    os.makedirs(disk_path)

            print_and_discord("\nScript started with the following configuration:", webhook_url)
            for source_folder in valid_src_folders:
                print_and_discord(f"Source folder: {source_folder}", webhook_url)
            for disk in disks:
                name = disk['name']
                path = disk['path']
                print_and_discord(f"Disk {name}: {path}", webhook_url)
            print_and_discord(f"Last used disk: {last_disk}", webhook_url)

            last_clear = datetime.now()
            clear_interval = timedelta(hours=console_clear_interval_hours)
            last_reverse_run = datetime.now()
            reverse_interval = timedelta(minutes=reverse_interval_minutes)
            while True:
                print_and_discord("======================================================", webhook_url)
                for source_folder in valid_src_folders:
                    print_and_discord(f"Checking source folder: {source_folder}", webhook_url)
                    last_disk = check_files_and_move(
                        source_folder,
                        disks,
                        last_disk,
                        webhook_url,
                        min_file_age_hours,
                        extra_safety_space_gb,
                    )
                if space_hunter_disks:
                    check_and_cleanup_disks(
                        space_hunter_disks,
                        webhook_url,
                        space_check_default_min_free_gb,
                    )

                if reverse_enabled and datetime.now() - last_reverse_run >= reverse_interval:
                    reverse_move_files(reverse_raid_config, webhook_url)
                    last_reverse_run = datetime.now()

                print_and_discord("======================================================", webhook_url)

                if datetime.now() - last_clear > clear_interval:
                    os.system('cls' if os.name == 'nt' else 'clear')
                    last_clear = datetime.now()
                    print_and_discord("Console cleared", webhook_url)

                time.sleep(scan_interval_seconds)

        except Exception as e:
            print_and_discord(f"An error occurred: {str(e)}", webhook_url)
            input("Press Enter to restart the program...")

if __name__ == "__main__":
    main()
