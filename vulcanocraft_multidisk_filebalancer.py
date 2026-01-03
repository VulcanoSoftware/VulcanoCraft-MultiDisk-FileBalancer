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
from asyncssh.sftp import SFTPName, SFTPAttrs, FXF_READ, FXF_WRITE, FXF_APPEND, FXF_CREAT, FXF_TRUNC

current_dir = os.getcwd()
config_path = os.path.join(current_dir, "config.yml")
virtual_index_path = os.path.join(current_dir, "virtual_index.yml")
virtual_index_lock = threading.Lock()


def load_virtual_index():
    if os.path.exists(virtual_index_path):
        with open(virtual_index_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f) or {}
            files = data.get('files', {}) or {}
            return {'files': files}
    return {'files': {}}


virtual_index = load_virtual_index()


def write_virtual_index():
    with open(virtual_index_path, 'w', encoding='utf-8') as f:
        yaml.safe_dump(virtual_index, f, allow_unicode=True)


def normalize_virtual_path(virtual_path):
    if not virtual_path:
        return '/'
    path = virtual_path.strip()
    if not path.startswith('/'):
        path = '/' + path
    return path


def map_virtual_path(virtual_path, physical_path):
    virtual = normalize_virtual_path(virtual_path)
    with virtual_index_lock:
        virtual_index['files'][virtual] = physical_path
        write_virtual_index()


def get_physical_path_for_virtual(virtual_path):
    virtual = normalize_virtual_path(virtual_path)
    with virtual_index_lock:
        return virtual_index['files'].get(virtual)


def remove_virtual_file(virtual_path):
    virtual = normalize_virtual_path(virtual_path)
    with virtual_index_lock:
        physical = virtual_index['files'].pop(virtual, None)
        if physical:
            write_virtual_index()
        return physical


def remove_virtual_file_by_physical_path(physical_path):
    changed_keys = []
    with virtual_index_lock:
        for virtual, physical in list(virtual_index['files'].items()):
            if physical == physical_path:
                changed_keys.append(virtual)
        for key in changed_keys:
            virtual_index['files'].pop(key, None)
        if changed_keys:
            write_virtual_index()


def update_virtual_index_after_move(old_path, new_path):
    with virtual_index_lock:
        changed = False
        for virtual, physical in list(virtual_index['files'].items()):
            if physical == old_path:
                virtual_index['files'][virtual] = new_path
                changed = True
        if changed:
            write_virtual_index()


def initialize_virtual_index_from_disks(disks):
    changed = False
    for disk in disks:
        path = disk.get('path')
        if not path or not os.path.isdir(path):
            continue
        try:
            names = os.listdir(path)
        except Exception:
            continue
        for name in names:
            physical_path = os.path.join(path, name)
            if not os.path.isfile(physical_path):
                continue
            with virtual_index_lock:
                if physical_path in virtual_index['files'].values():
                    continue
                virtual_path = '/' + name
                if virtual_path in virtual_index['files']:
                    continue
                virtual_index['files'][virtual_path] = physical_path
                changed = True
    if changed:
        write_virtual_index()


def create_s3_handler(upload_src_path, access_key=None, secret_key=None):
    class S3Handler(BaseHTTPRequestHandler):
        def _is_authorized(self):
            if not access_key and not secret_key:
                return True
            key = self.headers.get('X-Access-Key', '')
            secret = self.headers.get('X-Secret-Key', '')
            return key == access_key and secret == secret_key

        def _send_unauthorized(self):
            self.send_response(401)
            self.end_headers()

        def _safe_join_upload_path(self, raw_path):
            path = raw_path
            if path.startswith('/'):
                path = path[1:]
            rel_path = os.path.normpath(path.replace('/', os.sep))
            if rel_path.startswith('..') or os.path.isabs(rel_path):
                return None
            return os.path.join(upload_src_path, rel_path)

        def do_PUT(self):
            if not self._is_authorized():
                self._send_unauthorized()
                return
            parsed = urlparse(self.path)
            path = unquote(parsed.path)
            physical_path = self._safe_join_upload_path(path)
            if not physical_path:
                self.send_response(400)
                self.end_headers()
                return
            os.makedirs(os.path.dirname(physical_path), exist_ok=True)
            lengte_header = self.headers.get('Content-Length')
            lengte = int(lengte_header) if lengte_header and lengte_header.isdigit() else 0
            met_error = False
            try:
                with open(physical_path, 'wb') as f:
                    resterend = lengte
                    while resterend > 0:
                        chunk = self.rfile.read(min(65536, resterend))
                        if not chunk:
                            break
                        f.write(chunk)
                        resterend -= len(chunk)
                virt_path = normalize_virtual_path(unquote(parsed.path))
                map_virtual_path(virt_path, physical_path)
            except Exception:
                met_error = True
            if met_error:
                self.send_response(500)
            else:
                self.send_response(200)
            self.end_headers()

        def do_GET(self):
            if not self._is_authorized():
                self._send_unauthorized()
                return
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query or '')
            if 'list' in query:
                prefix = normalize_virtual_path(unquote(parsed.path))
                with virtual_index_lock:
                    keys = list(virtual_index['files'].keys())
                if prefix != '/':
                    normalized_prefix = prefix.rstrip('/') + '/'
                    filtered = [k for k in keys if k.startswith(normalized_prefix)]
                else:
                    filtered = keys
                content = "\n".join(sorted(filtered))
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(content.encode('utf-8'))
                return
            path = unquote(parsed.path)
            physical_path = get_physical_path_for_virtual(path)
            if not physical_path or not os.path.exists(physical_path):
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            with open(physical_path, 'rb') as f:
                shutil.copyfileobj(f, self.wfile)

        def do_DELETE(self):
            if not self._is_authorized():
                self._send_unauthorized()
                return
            parsed = urlparse(self.path)
            path = unquote(parsed.path)
            physical_path = remove_virtual_file(path)
            if physical_path and os.path.exists(physical_path):
                try:
                    os.remove(physical_path)
                    self.send_response(200)
                except Exception:
                    self.send_response(500)
            else:
                self.send_response(404)
            self.end_headers()

        def log_message(self, format, *args):
            return

    return S3Handler


def start_s3_server_thread(s3_config, upload_src_path, webhook_url):
    if not s3_config.get('enabled', False):
        return
    host = s3_config.get('host', '0.0.0.0')
    port = int(s3_config.get('port', 9000))
    access_key = s3_config.get('access_key') or None
    secret_key = s3_config.get('secret_key') or None
    handler_cls = create_s3_handler(upload_src_path, access_key, secret_key)

    def run_server():
        try:
            server = HTTPServer((host, port), handler_cls)
            print_and_discord(f"S3 server started on {host}:{port}", webhook_url)
            server.serve_forever()
        except Exception as e:
            print_and_discord(f"Could not start S3 server: {e}", webhook_url)

    threading.Thread(target=run_server, daemon=True).start()


def start_sftp_server_thread(sftp_config, upload_src_path, webhook_url):
    if not sftp_config.get('enabled', False):
        return

    host = sftp_config.get('host', '0.0.0.0')
    port = int(sftp_config.get('port', 2222))
    username_cfg = sftp_config.get('username', 'raiduser')
    password_cfg = sftp_config.get('password', 'changeme')
    host_key_path = sftp_config.get('host_key_path')

    class SimpleSSHServer(asyncssh.SSHServer):
        def begin_auth(self, username):
            return True

        def password_auth_supported(self):
            return True

        def validate_password(self, username, password):
            return username == username_cfg and password == password_cfg

    class SimpleSFTPServer(asyncssh.SFTPServer):
        def __init__(self, chan):
            self._upload_src_path = upload_src_path
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

        def canonicalize(self, path):
            virt = self._normalize_virtual(path)
            return virt.encode('utf-8')

        def realpath(self, path):
            virt = self._normalize_virtual(path)
            return virt.encode('utf-8')

        def _list_children(self, virt_dir):
            with virtual_index_lock:
                keys = list(virtual_index['files'].keys())
            if virt_dir != '/':
                prefix = virt_dir.rstrip('/') + '/'
                relevant = [k for k in keys if k.startswith(prefix)]
            else:
                prefix = '/'
                relevant = keys
            names = {}
            for k in relevant:
                if virt_dir == '/':
                    rest = k.lstrip('/')
                else:
                    rest = k[len(prefix):]
                if not rest:
                    continue
                first = rest.split('/', 1)[0]
                if not first:
                    continue
                full_virtual = virt_dir.rstrip('/')
                if not full_virtual:
                    full_virtual = ''
                full_virtual = full_virtual + '/' + first
                names[first] = full_virtual
            return keys, names

        def listdir(self, path):
            virt_dir = self._normalize_virtual(path)
            keys, names = self._list_children(virt_dir)
            result = []
            for name, full_virtual in sorted(names.items()):
                is_dir = False
                fysiek_pad = None
                with virtual_index_lock:
                    physical_path = virtual_index['files'].get(full_virtual)
                    if not physical_path:
                        prefix = full_virtual.rstrip('/') + '/'
                        for k in keys:
                            if k.startswith(prefix):
                                is_dir = True
                                break
                if physical_path and os.path.exists(physical_path):
                    if os.path.isdir(physical_path):
                        is_dir = True
                    st = os.stat(physical_path)
                    attrs = SFTPAttrs.from_local(st)
                else:
                    mode = stat.S_IFDIR | 0o755 if is_dir else stat.S_IFREG | 0o644
                    now = int(time.time())
                    attrs = SFTPAttrs(
                        permissions=mode,
                        atime=now,
                        mtime=now,
                    )
                result.append(SFTPName(name.encode('utf-8'), '', attrs))
            return result

        async def stat(self, path, follow_symlinks=True):
            virt = self._normalize_virtual(path)
            physical_path = get_physical_path_for_virtual(virt)
            if physical_path and os.path.exists(physical_path):
                return os.stat(physical_path)
            virt_dir = virt
            keys, names = self._list_children(virt_dir)
            if names:
                mode = stat.S_IFDIR | 0o755
                now = int(time.time())
                return os.stat_result((mode, 0, 0, 0, 0, 0, 0, now, now, now))
            raise asyncssh.SFTPNoSuchFile(virt)

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
                name = virt.strip('/').split('/')[-1]
                if not name:
                    raise asyncssh.SFTPFailure('Invalid file name')
                physical_path = os.path.join(self._upload_src_path, name)
                map_virtual_path(virt, physical_path)
            else:
                physical_path = get_physical_path_for_virtual(virt)
                if not physical_path or not os.path.exists(physical_path):
                    raise asyncssh.SFTPNoSuchFile(virt)
            mode = self._mode_from_pflags(pflags)
            f = open(physical_path, mode)
            return f

        async def remove(self, path):
            virt = self._normalize_virtual(path)
            physical_path = remove_virtual_file(virt)
            if physical_path and os.path.exists(physical_path):
                os.remove(physical_path)
                return
            raise asyncssh.SFTPNoSuchFile(virt)

    async def start_server():
        server_host_keys = None
        if host_key_path and os.path.exists(host_key_path):
            server_host_keys = [host_key_path]
        else:
            try:
                generated_key = asyncssh.generate_private_key('ssh-ed25519')
                server_host_keys = [generated_key]
            except Exception:
                server_host_keys = None

        await asyncssh.listen(
            host,
            port,
            server_factory=SimpleSSHServer,
            server_host_keys=server_host_keys,
            sftp_factory=SimpleSFTPServer,
        )

    def run_server():
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(start_server())
            print_and_discord(f"SFTP server started on {host}:{port}", webhook_url)
            loop.run_forever()
        except Exception as e:
            print_and_discord(f"Could not start SFTP server: {e}", webhook_url)

    threading.Thread(target=run_server, daemon=True).start()

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
    s3_server_config = config_data.get('s3_server') or {}
    sftp_server_config = config_data.get('sftp_server') or {}

    min_file_age_hours = settings.get('min_file_age_hours', 4)
    extra_safety_space_gb = settings.get('extra_safety_space_gb', 5)
    scan_interval_seconds = settings.get('scan_interval_seconds', 120)
    console_clear_interval_hours = settings.get('console_clear_interval_hours', 6)
    space_check_default_min_free_gb = settings.get('space_check_default_min_free_gb', 40)

    s3_enabled = s3_server_config.get('enabled', False)
    s3_host = s3_server_config.get('host', '0.0.0.0')
    s3_port = s3_server_config.get('port', 9000)
    s3_access_key = s3_server_config.get('access_key', '')
    s3_secret_key = s3_server_config.get('secret_key', '')
    s3_upload_src = s3_server_config.get('upload_src', src)

    sftp_enabled = sftp_server_config.get('enabled', False)
    sftp_host = sftp_server_config.get('host', '0.0.0.0')
    sftp_port = sftp_server_config.get('port', 2222)
    sftp_username = sftp_server_config.get('username', 'raiduser')
    sftp_password = sftp_server_config.get('password', 'changeme')
    sftp_upload_src = sftp_server_config.get('upload_src', src)

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
    lines.append("# S3-LIKE SERVER FOR VIRTUAL DISK")
    lines.append("######################################################################")
    lines.append("#")
    lines.append("# With \"s3_server\" you can enable a simple HTTP server that")
    lines.append("# exposes files via an S3-like interface (PUT/GET/DELETE).")
    lines.append("# This is NOT real Amazon S3, but behaves similarly in spirit:")
    lines.append("# - You talk to the server over HTTP on host:port.")
    lines.append("# - Each path (e.g. /folder1/file.txt) is treated as a single object/file.")
    lines.append("#")
    lines.append("# Authentication:")
    lines.append("# - access_key: similar to a username.")
    lines.append("# - secret_key: similar to a password.")
    lines.append("# - Clients should send these headers:")
    lines.append("#     X-Access-Key: <access_key>")
    lines.append("#     X-Secret-Key: <secret_key>")
    lines.append("# - Leave both empty to disable authentication (only recommended on")
    lines.append("#   a trusted network).")
    lines.append("#")
    lines.append("# Files uploaded via this server are stored in the upload_src folder")
    lines.append("# configured below and later picked up by the FileBalancer and")
    lines.append("# distributed over the configured disks.")
    lines.append("s3_server:")
    lines.append(f"  enabled: {'true' if s3_enabled else 'false'}")
    lines.append(f"  host: {s3_host}")
    lines.append(f"  port: {s3_port}")
    lines.append(f"  access_key: '{s3_access_key}'")
    lines.append(f"  secret_key: '{s3_secret_key}'")
    lines.append(f"  upload_src: {s3_upload_src}")

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
    lines.append("sftp_server:")
    lines.append(f"  enabled: {'true' if sftp_enabled else 'false'}")
    lines.append(f"  host: {sftp_host}")
    lines.append(f"  port: {sftp_port}")
    lines.append(f"  username: '{sftp_username}'")
    lines.append(f"  password: '{sftp_password}'")
    lines.append(f"  upload_src: {sftp_upload_src}")

    with open(config_path, 'w', encoding='utf-8') as config_file:
        config_file.write("\n".join(lines) + "\n")

def read_config(config_path=config_path):
    if os.path.exists(config_path):
        with open(config_path, 'r') as yaml_file:
            config_data = yaml.safe_load(yaml_file)
            print(f"Config data loaded: {config_data}")
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
    files = [f for f in os.listdir(src) if os.path.isfile(os.path.join(src, f))]

    time_limit = timedelta(hours=min_file_age_hours)
    now = datetime.now()
    files_to_move = []

    for file in files:
        source_path = os.path.join(src, file)
        modified_date = get_last_modified_time(source_path)

        if now - modified_date > time_limit:
            files_to_move.append(file)
        else:
            print_and_discord(f"{file} was modified too recently and will not be moved.", webhook_url)

    print_and_discord("\nStarting to move files:", webhook_url)
    for file in files_to_move:
        source_path = os.path.join(src, file)
        file_size_gb = get_file_size(source_path) // (2**30)
        required_space = file_size_gb + extra_safety_space_gb

        file_moved = False
        original_disk = new_last_disk
        target_disk = get_next_disk(new_last_disk, [disk['name'] for disk in disks])

        for _ in range(len(disks)):
            target_info = next(disk for disk in disks if disk['name'] == target_disk)
            target_path = target_info['path']

            print_and_discord(
                f"File: {file}, Size: {file_size_gb} GB, Required space: {required_space} GB",
                webhook_url,
            )
            print_and_discord(f"Attempting to move to {target_disk}", webhook_url)

            if has_sufficient_free_space(target_path, required_space):
                destination_path = os.path.join(target_path, file)
                shutil.move(source_path, destination_path)
                update_virtual_index_after_move(source_path, destination_path)
                print_and_discord(f"{file} moved to {target_disk}", webhook_url)
                new_last_disk = target_disk
                file_moved = True
                break
            else:
                print_and_discord(f"Not enough space for {file} on {target_disk}", webhook_url)
                target_disk = get_next_disk(target_disk, [disk['name'] for disk in disks])

        if not file_moved:
            print_and_discord(f"No disk has enough space for {file}, skipping file.", webhook_url)

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
                update_virtual_index_after_move(oldest_file, new_path)
                print_and_discord(f"The oldest file was moved: {oldest_file} to {new_path}", webhook_url)
            elif action == 'delete':
                os.remove(oldest_file)
                remove_virtual_file_by_physical_path(oldest_file)
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

        files = [f for f in os.listdir(source_folder) if os.path.isfile(os.path.join(source_folder, f))]

        for filename in files:
            source_path = os.path.join(source_folder, filename)
            destination_file_path = os.path.join(destination_path, filename)

            file_time = os.path.getmtime(source_path)
            file_age_hours = (time.time() - file_time) / 3600

            if file_age_hours < min_age_hours:
                print_and_discord(
                    f"Reverse RAID: skipping {filename}, too new ({file_age_hours:.1f} hours).",
                    webhook_url,
                )
                total_skipped_too_new += 1
                continue

            total_files += 1
            files_in_folder += 1

            if os.path.exists(destination_file_path):
                print_and_discord(
                    f"Reverse RAID: skipping {filename}, already exists in destination folder.",
                    webhook_url,
                )
                continue

            try:
                shutil.move(source_path, destination_file_path)
                update_virtual_index_after_move(source_path, destination_file_path)
                print_and_discord(f"Reverse RAID: moved {filename}", webhook_url)
                total_moved += 1
                moved_in_folder += 1
            except Exception as e:
                print_and_discord(
                    f"Reverse RAID: error while moving {filename}: {e}",
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
    space_check_default_min_free_gb = settings.get('space_check_default_min_free_gb', 40)

    reverse_raid_config = config.get('reverse_raid', {})
    reverse_enabled = reverse_raid_config.get('enabled', False)
    reverse_interval_minutes = reverse_raid_config.get('run_interval_minutes', 10)

    s3_server_config = config.get('s3_server', {})
    sftp_server_config = config.get('sftp_server', {})

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

    if not space_hunter_disks:
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

        s3_server_cfg = {}
        print("\nS3-like HTTP server:")
        print("- This is NOT real Amazon S3, but a simple S3-like HTTP server.")
        print("- The 'access key' functions like a username.")
        print("- The 'secret key' functions like a password.")
        use_s3 = input("Do you want to enable the S3-like HTTP server? (yes/no): ").strip().lower() == 'yes'
        if use_s3:
            default_s3_host = s3_server_config.get('host', '0.0.0.0')
            default_s3_port = s3_server_config.get('port', 9000)
            host_input = input(f"S3 host (default {default_s3_host}): ").strip()
            port_input = input(f"S3 port (default {default_s3_port}): ").strip()
            access_key_input = input("S3 access key (similar to a username, leave empty for no auth): ").strip()
            secret_key_input = input("S3 secret key (similar to a password, leave empty for no auth): ").strip()
            upload_src_input = input(f"S3 upload folder (default {src}): ").strip()
            s3_server_cfg = {
                'enabled': True,
                'host': host_input or default_s3_host,
                'port': int(port_input) if port_input.isdigit() else default_s3_port,
                'access_key': access_key_input,
                'secret_key': secret_key_input,
                'upload_src': upload_src_input or src,
            }
        else:
            s3_server_cfg = s3_server_config or {
                'enabled': False,
                'host': '0.0.0.0',
                'port': 9000,
                'access_key': '',
                'secret_key': '',
                'upload_src': src,
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
            upload_src_input = input(f"SFTP upload folder (default {src}): ").strip()
            sftp_server_cfg = {
                'enabled': True,
                'host': host_input or default_sftp_host,
                'port': int(port_input) if port_input.isdigit() else default_sftp_port,
                'username': username_input or default_sftp_username,
                'password': password_input or default_sftp_password,
                'upload_src': upload_src_input or src,
            }
        else:
            sftp_server_cfg = sftp_server_config or {
                'enabled': False,
                'host': '0.0.0.0',
                'port': 2222,
                'username': 'raiduser',
                'password': 'changeme',
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
            try:
                num_reverse_sources = int(input("How many source folders do you want to configure for reverse RAID? "))
            except ValueError:
                num_reverse_sources = 0
            if num_reverse_sources < 0:
                num_reverse_sources = 0
            for i in range(num_reverse_sources):
                path = input(f"Enter the path for reverse RAID source folder {i + 1}: ").strip()
                if path:
                    reverse_source_paths.append(path)
            if not reverse_source_paths:
                reverse_source_paths = [disk['pad'] for disk in disks if 'pad' in disk and disk.get('pad')]
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
            's3_server': s3_server_cfg,
            'sftp_server': sftp_server_cfg,
        }
        if reverse_raid_config:
            new_config['reverse_raid'] = reverse_raid_config
        save_config_if_missing(new_config, config_path=config_path)

    initialize_virtual_index_from_disks(disks)

    s3_enabled = s3_server_config.get('enabled', False)
    s3_upload_src = s3_server_config.get('upload_src', src)
    if s3_enabled and s3_upload_src and s3_upload_src not in src_folders:
        src_folders.append(s3_upload_src)
    start_s3_server_thread(s3_server_config, s3_upload_src, webhook_url)

    sftp_enabled = sftp_server_config.get('enabled', False)
    sftp_upload_src = sftp_server_config.get('upload_src', src)
    if sftp_enabled and sftp_upload_src and sftp_upload_src not in src_folders:
        src_folders.append(sftp_upload_src)
    start_sftp_server_thread(sftp_server_config, sftp_upload_src, webhook_url)

    while True:
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
                if not os.path.exists(disk['pad']):
                    print_and_discord(f"The folder {disk['pad']} does not exist. Creating the folder.", webhook_url)
                    os.makedirs(disk['pad'])

            print_and_discord("\nScript started with the following configuration:", webhook_url)
            for source_folder in valid_src_folders:
                print_and_discord(f"Source folder: {source_folder}", webhook_url)
            for disk in disks:
                name = disk.get('naam') or disk.get('name')
                path = disk.get('pad') or disk.get('path')
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
                        [{'name': d.get('naam') or d.get('name'), 'path': d.get('pad') or d.get('path')} for d in disks],
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
