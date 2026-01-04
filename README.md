# VulcanoCraft MultiDisk FileBalancer

VulcanoCraft MultiDisk FileBalancer distributes completed files intelligently across multiple disks without the fragility of true RAID 0.

It watches an input folder, waits until files are "old enough", and then moves them to one of several configured disk paths using a rotation scheme and free-space checks. Each file always lives on a single disk, so losing one disk does not destroy all data.

---

## Features

- File-level distribution across multiple disks (no block-level striping)
- Tolerant of missing or newly added disks (handled via paths in `config.yml`)
- Moves only files that are older than a configurable time threshold (default 4 hours)
- Uses configurable free-space checks (default: file size + 5 GB on the target disk)
- Round-robin disk selection with automatic fallback when a disk is full
- Optional Discord webhook notifications for status and errors
- Fully configurable via `config.yml`, which contains detailed inline documentation
- Integrated disk-space monitoring and cleanup (Space Hunter functionality)
- Integrated "reverse RAID" mode to collect files back from multiple target folders into a single destination folder, replacing the separate reverse-raid-0-sim tool

Implementation details can be found in [vulcanocraft_multidisk_filebalancer.py](file:///c:/Users/LiamWinters/Downloads/raid-0-sim-main/vulcanocraft_multidisk_filebalancer.py).

---

## How It Works

The main logic lives in [vulcanocraft_multidisk_filebalancer.py](file:///c:/Users/LiamWinters/Downloads/raid-0-sim-main/vulcanocraft_multidisk_filebalancer.py).

At a high level:

- On startup, the tool loads `config.yml` if it exists. If it does not exist yet, it interactively asks for:
  - How many input folders you want to use
  - The path(s) to these input folders
  - The optional Discord webhook URL
  - The number of disks and their paths
  and then writes an initial `config.yml` file with English inline comments. Existing `config.yml` files are not overwritten, so your comments stay intact.
- The main behavior is controlled by the `settings` section in `config.yml`:
  - `min_file_age_hours` (default 4 hours)
  - `extra_safety_space_gb` (default 5 GB)
  - `scan_interval_seconds` (default 120 seconds)
  - `console_clear_interval_hours` (default 6 hours)
- In an infinite loop, every `scan_interval_seconds` seconds:
  - It scans the input folder for files.
  - It filters out files that were modified more recently than `min_file_age_hours` ago.
  - For each remaining file:
    - It calculates the file size in GB.
    - It looks for a disk with at least `file_size_gb + extra_safety_space_gb` GB free.
    - It chooses disks in a round-robin sequence, starting from the last disk used.
    - If the chosen disk does not have enough space, it tries the next disk, and so on.
    - If a suitable disk is found, the file is moved there.
    - If no disk has enough space, the file is skipped for that cycle.
- The last used disk is tracked in memory and can be initialized via `last_disk` in the configuration.
- Important messages and errors are printed to the console and optionally sent to Discord.

Key functions:

- `check_files_and_move(...)`  
  Scans the input folder, filters files by age, and moves them to the configured disks using the thresholds from `settings`.

- `get_next_disk(current_disk, disks)`  
  Implements round-robin selection over disk names.

- `has_sufficient_free_space(disk, required_gb)`  
  Checks free space on the disk path.

---

## Installation

### Requirements

- Python 3.8+ (recommended)
- Operating system:
  - Windows (primary target; includes batch files)
  - Linux/macOS should also work for the Python script itself, but the provided `.bat` files are Windows-only.
- Python packages:
  - `PyYAML` (for `yaml`)
  - `requests`

### Install Python dependencies

From the project folder:

```bash
pip install pyyaml requests
```

### Run from source (Python script)

From the project folder:

```bash
python vulcanocraft_multidisk_filebalancer.py
```

The script will:

- Try to read `config.yml` from the current working directory.
- If `config.yml` is missing or incomplete, it will ask you for:
  - Input folder path
  - Discord webhook URL (optional)
  - Number of disks and disk paths

### Build a standalone executable (optional)

The repository includes a `pyinstaller.txt` helper command. To create a single-file executable with an icon:

```bash
pyinstaller -i icon.ico --name VulcanoCraft-MultiDisk-FileBalancer --onefile vulcanocraft_multidisk_filebalancer.py
```

After building:

- `VulcanoCraft-MultiDisk-FileBalancer.exe` will be created in the `dist` folder.
- You can use `VulcanoCraft-MultiDisk-FileBalancer.bat` to start the executable from the project folder.

---

## Configuration

Configuration is stored in `config.yml` in the project directory. It is created automatically on first run. After that you normally edit it manually; the script does not overwrite an existing `config.yml` so that your comments and layout are preserved.

### Example `config.yml`

```yaml
src: "D:\\InputFolder"
webhook_url: "https://discord.com/api/webhooks/..."
disks:
  - name: "disk1"
    path: "E:\\Storage1"
  - name: "disk2"
    path: "F:\\Storage2"
last_disk: "disk1"
settings:
  min_file_age_hours: 4
  extra_safety_space_gb: 5
  scan_interval_seconds: 120
  console_clear_interval_hours: 6
  space_check_default_min_free_gb: 40
space_hunter_disks:
  - path: "E:\\Storage1"
    min_free_gb: 40
    action: "delete"
    move_destination: null
reverse_raid:
  enabled: false
  source_paths:
    - "E:\\Storage1"
    - "F:\\Storage2"
  destination_path: "D:\\Collected"
  min_file_age_hours: 12
  run_interval_minutes: 10
```

### Fields

- `src`  
  Absolute path to the input folder where new files appear.

- `webhook_url`  
  Optional Discord webhook URL.  
  - If empty or omitted, no Discord messages are sent.
  - If present, the tool posts status messages and errors to this webhook.

- `disks`  
  List of disks. Each disk has:
  - `name` – logical name (e.g. `disk1`, `disk2`).
  - `path` – absolute path to the folder on that disk where files will be moved.

- `last_disk`  
  The name of the last disk that was used.  
  - This can be used to control where the next file goes when the tool starts.

If a disk path in `disks` does not exist at runtime, the tool will create the directory automatically.

- `settings`  
  Technical behavior switches for the file balancer and Space Hunter:
  - `min_file_age_hours` – minimum file age (hours) before it is eligible to move.
  - `extra_safety_space_gb` – additional free space required on the target disk (GB).
  - `scan_interval_seconds` – delay between scans of the input folder (seconds).
  - `console_clear_interval_hours` – interval for clearing the console (hours).
  - `space_check_default_min_free_gb` – default minimum free space (GB) used when interactively configuring Space Hunter disks.

- `space_hunter_disks`  
  Optional list of disks to monitor and clean up when free space is low.  
  Each entry has:
  - `path` – disk or folder path to monitor.
  - `min_free_gb` – minimum free space in GB; if actual free space drops below this, an action is triggered (falls back to `space_check_default_min_free_gb` if omitted).
  - `action` – either `delete` (delete oldest file) or `move` (move oldest file).
  - `move_destination` – destination folder if `action` is `move`; otherwise `null` or omitted.

- `reverse_raid`  
  Configuration for the integrated reverse RAID mode that collects files back from multiple folders into one:
  - `enabled` – whether the reverse RAID feature runs at all.
  - `source_paths` – list of folders to pull files from (for example the balancer target folders).
  - `destination_path` – single folder where files should be moved to.
  - `min_file_age_hours` – minimum file age before a file is eligible to be moved back.
  - `run_interval_minutes` – how often the reverse process runs, independently of the main balancer scan interval.

---

## Usage

1. **Prepare one or more input folders**  
   Create the folder(s) where new files will be written (e.g. your download/render/output directory). On first run the tool will ask how many input folders you want and their paths.

2. **Prepare disk folders**  
   Decide on one or more target folders on your storage disks, for example:
   - `E:\Storage1`
   - `F:\Storage2`
   - `G:\Storage3`

3. **Run the tool**  
   Start it via:
-   - `python vulcanocraft_multidisk_filebalancer.py`, or
-   - `VulcanoCraft-MultiDisk-FileBalancer.exe` (if you built the executable).

4. **Fill in configuration (first run)**  
   If `config.yml` does not exist or is incomplete, the script will ask you:
   - How many input folders you want to use
   - Each input folder path
   - Discord webhook URL (press Enter to skip)
   - Number of disks
   - Path to each disk

5. **Let files accumulate**  
   The tool only moves files that have not been modified for at least `min_file_age_hours` hours (default 4).  
   - This protects files that are still being written or processed.

6. **Automatic distribution**  
   Every `scan_interval_seconds` seconds (default 120), the tool scans the input folder and moves eligible files:
   - It uses round-robin over the configured disk names.
   - It checks that each target disk has at least `file_size_gb + extra_safety_space_gb` GB free (default `file_size_gb + 5`).
   - If a disk does not have enough space, it tries the next one.
   - If no disk is suitable, the file is skipped for that cycle.

7. **Monitor output**  
   - Watch the console for progress and errors.
   - If a Discord webhook is configured, you will also get messages there.

---

## How It Differs From RAID 0

VulcanoCraft MultiDisk FileBalancer is *inspired* by the idea of spreading data across multiple disks, but it is **not** a true RAID 0 implementation.

Key differences:

- **File-level vs block-level**  
  - RAID 0 splits each file into blocks and stripes those blocks across all disks.  
  - This tool always keeps each file on a single disk; it only decides *which* disk.

- **Resilience to disk loss**  
  - In RAID 0, losing a single disk usually corrupts the entire array.  
  - With this tool, only the files on the lost disk are affected; other disks and files remain intact.

- **No strict disk order or RAID metadata**  
  - RAID 0 arrays depend on exact disk sets and order.  
  - Here, disks are just paths in `config.yml`. You can add, remove, or change them without rebuilding an array.

- **Capacity-aware per file**  
  - RAID 0 does not consider free space per disk on a per-file basis.  
  - This tool checks available space on each disk and requires `file_size_gb + 5` GB before it moves a file there.

- **Workflow-aware (time threshold)**  
  - RAID 0 has no concept of “files that are still being written”.  
  - This tool waits until a file has not been modified for 4 hours before moving it.

Because of these differences, the new name avoids suggesting that this is a strict RAID 0 simulator.

---

## Notes and Limitations

- The tool only processes files in the **top level** of the input folder (no recursion into subdirectories).
- The age threshold, polling interval and console clear interval are configurable via the `settings` section in `config.yml` (defaults: 4 hours, 120 seconds, 6 hours).
- On Windows, the console is cleared according to `console_clear_interval_hours`; on other platforms, the behavior depends on the availability of the `clear` command.
- If a serious error occurs, the tool prints the exception and waits for user input before restarting.

---
