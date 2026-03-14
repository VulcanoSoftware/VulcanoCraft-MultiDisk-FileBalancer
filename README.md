# VulcanoCraft MultiDisk FileBalancer

VulcanoCraft MultiDisk FileBalancer moves files from one or more input folders to multiple disk folders.
It is inspired by RAID 0, but it is not real RAID 0.

Each file stays on one disk.  
If one disk fails, only files on that disk are affected.

---

## What This Tool Does

- Watches input folders
- Waits until files are old enough
- Moves files to disk folders in round-robin order
- Checks free space before moving
- Supports Discord notifications
- Supports optional Space Hunter cleanup
- Supports optional reverse RAID (move files back to one folder)
- Supports optional WebDAV, SFTP, and FUSE virtual view

---

## Quick Start

From the project folder:

```bash
pip install -r requirements.txt
python vulcanocraft_multidisk_filebalancer.py
```

On Debian/Ubuntu with externally-managed Python, you may need:

```bash
pip install -r requirements.txt --break-system-packages
```

On first run, the tool asks setup questions and creates `config.yml`.

---

## How It Works (Simple)

1. Load `config.yml` (or run first-time setup)
2. Print a startup preflight report
3. If FUSE is enabled, check/install FUSE requirements
4. Start enabled services (FUSE/WebDAV/SFTP)
5. Loop forever:
   - scan input folders
   - skip files that are too new
   - move eligible files with space checks
   - run cleanup/reverse tasks if enabled

---

## Important FUSE Behavior

- FUSE is optional.
- If `fuse_server.enabled: true`, FUSE is treated as required.
- The app tries to auto-install missing FUSE dependencies per OS.
- If install/start fails, startup stops with a clear error.
- If the issue is privileges, restart as Administrator (Windows) or root/sudo (Linux/macOS).

---

## Minimal Config Example

```yaml
src_folders:
  - "D:\\Input1"
  - "D:\\Input2"
src: "D:\\Input1"

disks:
  - name: "disk1"
    path: "E:\\Storage1"
  - name: "disk2"
    path: "F:\\Storage2"

last_disk: "disk1"
webhook_url: ""

settings:
  min_file_age_hours: 4
  extra_safety_space_gb: 5
  scan_interval_seconds: 120
  console_clear_interval_hours: 6
  space_check_default_min_free_gb: 40

space_hunter_disks: []

reverse_raid:
  enabled: false
  source_paths: []
  destination_path: ""
  min_file_age_hours: 12
  run_interval_minutes: 10

webdav_server:
  enabled: false
  host: "0.0.0.0"
  port: 8080
  username: "admin"
  password: "admin"
  upload_src: "D:\\Input1"
  use_fuse_mount_as_root: true

sftp_server:
  enabled: false
  host: "0.0.0.0"
  port: 2222
  username: "raiduser"
  password: "changeme"
  upload_src: "D:\\Input1"
  use_fuse_mount_as_root: true

fuse_server:
  enabled: false
  mount_point: "D:\\VulcanoCraft\\mount"
  upload_src: "D:\\Input1"
```

---

## Main Config Fields

- `src_folders`: list of input folders (preferred)
- `src`: legacy single input fallback
- `disks`: target folders for moved files
- `last_disk`: remembers round-robin position
- `settings`: scan interval, age threshold, safety space
- `space_hunter_disks`: optional cleanup rules
- `reverse_raid`: optional move-back rules
- `webdav_server`, `sftp_server`, `fuse_server`: optional virtual access

---

## Notes

- OS support: Windows, Linux, macOS
- `.bat` launcher is Windows-only
- FUSE depends on OS-level packages/drivers
- The script logs errors and retries after failures

---

Implementation file: [vulcanocraft_multidisk_filebalancer.py](file:///c:/Users/LiamWinters/OneDrive%20-%20WICO%20vzw/Bureaublad/server%20stuff/multidisk_balancer/VulcanoCraft-MultiDisk-FileBalancer/vulcanocraft_multidisk_filebalancer.py)
