import os
import sys
import json
import time
import math
import ctypes
import hashlib
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Dict, Any

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QLabel, QLineEdit, QComboBox, QCheckBox,
    QTextEdit, QMessageBox, QProgressBar, QFileDialog, QRadioButton, QButtonGroup,
    QDialog, QDialogButtonBox, QFormLayout, QFrame
)

# =========================
# Platform helpers
# =========================

def is_windows() -> bool:
    return os.name == "nt"

def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def relaunch_as_admin():
    if not is_windows():
        return
    params = " ".join([f'"{arg}"' for arg in sys.argv])
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        sys.exit(0)
    except Exception as e:
        QMessageBox.critical(None, "Elevation failed", f"Unable to elevate privileges: {e}")

def run_powershell(ps_command: str) -> subprocess.CompletedProcess:
    exe = shutil.which("powershell") or shutil.which("powershell.exe")
    if not exe:
        raise RuntimeError("PowerShell not found in PATH.")
    return subprocess.run(
        [exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_command],
        capture_output=True, text=True, encoding="utf-8", errors="replace"
    )

def run_powershell_json(ps_command: str) -> Any:
    cp = run_powershell(ps_command)
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr.strip() or "Unknown PowerShell error.")
    text = cp.stdout.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON from PowerShell: {e}\nOutput: {text[:1000]}")

def human_bytes(n: int) -> str:
    step = 1024.0
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(n)
    for u in units:
        if size < step:
            return f"{size:.1f} {u}"
        size /= step
    return f"{size:.1f} PB"

# =========================
# Disk model
# =========================

@dataclass
class DiskInfo:
    number: int
    size: int
    bus_type: str
    friendly_name: str
    is_system: bool
    is_boot: bool
    is_readonly: bool
    is_removable: bool
    partition_style: str
    letters: List[str]

def list_disks() -> List[DiskInfo]:
    if not is_windows():
        raise RuntimeError("Windows only.")
    ps = r"""
$disks = Get-Disk | Select-Object Number, Size, BusType, FriendlyName, IsSystem, IsBoot, IsReadOnly, IsRemovable, PartitionStyle
$result = @()
foreach ($d in $disks) {
    $letters = @()
    try {
        $letters = (Get-Partition -DiskNumber $d.Number | Where-Object { $_.DriveLetter } | Select-Object -ExpandProperty DriveLetter)
    } catch {}
    if ($letters -eq $null) { $letters = @() }
    $obj = [PSCustomObject]@{
        Number = $d.Number
        Size = $d.Size
        BusType = [string]$d.BusType
        FriendlyName = [string]$d.FriendlyName
        IsSystem = [bool]$d.IsSystem
        IsBoot = [bool]$d.IsBoot
        IsReadOnly = [bool]$d.IsReadOnly
        IsRemovable = [bool]$d.IsRemovable
        PartitionStyle = [string]$d.PartitionStyle
        Letters = $letters
    }
    $result += $obj
}
$result | ConvertTo-Json -Depth 4
"""
    data = run_powershell_json(ps)
    if data is None:
        return []
    if isinstance(data, dict):
        data = [data]
    out: List[DiskInfo] = []
    for d in data:
        out.append(DiskInfo(
            number=int(d.get("Number")),
            size=int(d.get("Size") or 0),
            bus_type=str(d.get("BusType") or ""),
            friendly_name=str(d.get("FriendlyName") or ""),
            is_system=bool(d.get("IsSystem")),
            is_boot=bool(d.get("IsBoot")),
            is_readonly=bool(d.get("IsReadOnly")),
            is_removable=bool(d.get("IsRemovable")),
            partition_style=str(d.get("PartitionStyle") or ""),
            letters=list(d.get("Letters") or [])
        ))
    return out

# =========================
# Raw IO helpers
# =========================

def physical_drive_path(disk_number: int) -> str:
    return r"\\.\PhysicalDrive{}".format(disk_number)

def set_disk_offline(disk_number: int, offline: bool, read_only: Optional[bool] = None):
    # Bring disk offline/online; optionally toggle read-only
    if offline:
        ps = f"Set-Disk -Number {disk_number} -IsOffline $true -ErrorAction Stop"
        cp = run_powershell(ps)
        if cp.returncode != 0:
            raise RuntimeError(cp.stderr.strip() or f"Failed to set disk {disk_number} offline.")
    else:
        ps = f"Set-Disk -Number {disk_number} -IsOffline $false -ErrorAction Stop"
        cp = run_powershell(ps)
        if cp.returncode != 0:
            raise RuntimeError(cp.stderr.strip() or f"Failed to set disk {disk_number} online.")

    if read_only is not None:
        ros = "$true" if read_only else "$false"
        ps2 = f"Set-Disk -Number {disk_number} -IsReadOnly {ros} -ErrorAction Stop"
        cp2 = run_powershell(ps2)
        if cp2.returncode != 0:
            raise RuntimeError(cp2.stderr.strip() or f"Failed to set disk {disk_number} read-only={read_only}.")

def open_raw_device(disk_number: int, write: bool):
    mode = "r+b" if write else "rb"
    # Avoid truncation: never use "wb" for raw device
    return open(physical_drive_path(disk_number), mode, buffering=0)

def parse_block_size(label: str) -> int:
    # e.g., "4 MiB"
    parts = label.split()
    if not parts:
        return 4 * 1024 * 1024
    n = int(parts[0])
    unit = (parts[1].lower() if len(parts) > 1 else "mib")
    if unit.startswith("k"):
        return n * 1024
    if unit.startswith("m"):
        return n * 1024 * 1024
    if unit.startswith("g"):
        return n * 1024 * 1024 * 1024
    return n

# =========================
# Worker
# =========================

class ImagingWorker(QThread):
    progress = Signal(int)          # 0..100
    status = Signal(str)            # log lines
    speed_eta = Signal(str)         # "X MB/s — ETA 00:00:00"
    finished = Signal(dict)         # result or error
    failed = Signal(str)

    def __init__(self, args: Dict[str, Any]):
        super().__init__()
        self.args = args
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        try:
            if self.args["mode"] == "WRITE":
                self._run_write()
            else:
                self._run_read()
        except Exception as e:
            self.failed.emit(str(e))

    def _run_write(self):
        disk: int = self.args["disk"]
        img_path: str = self.args["image_path"]
        block_size: int = self.args["block_size"]
        hash_alg: Optional[str] = self.args.get("hash_alg")  # "MD5" | "SHA256" | None
        verify: bool = bool(self.args.get("verify_after", False))
        simulate: bool = bool(self.args.get("simulate", False))
        device_size: int = int(self.args["device_size"])

        if not os.path.exists(img_path):
            raise RuntimeError("Image file not found.")
        img_size = os.path.getsize(img_path)
        if img_size > device_size:
            raise RuntimeError("Image is larger than target device.")

        self.status.emit(f"Preparing to WRITE image -> disk #{disk}")
        self.status.emit(f"Image: {img_path} ({human_bytes(img_size)})")
        self.progress.emit(0)

        # Hash of image while streaming
        h_img = hashlib.md5() if hash_alg == "MD5" else (hashlib.sha256() if hash_alg == "SHA256" else None)

        start = time.time()
        bytes_done = 0
        last_update = start

        # Take device offline for exclusive write, ensure not read-only
        self.status.emit("Taking device offline...")
        if not simulate:
            set_disk_offline(disk, offline=True)
            set_disk_offline(disk, offline=True, read_only=False)

        try:
            with open(img_path, "rb", buffering=0) as fimg:
                if simulate:
                    dev = None
                else:
                    dev = open_raw_device(disk, write=True)

                try:
                    while True:
                        if self._cancel:
                            raise RuntimeError("Operation cancelled by user.")
                        chunk = fimg.read(block_size)
                        if not chunk:
                            break
                        if h_img:
                            h_img.update(chunk)
                        if not simulate:
                            dev.write(chunk)
                        bytes_done += len(chunk)

                        now = time.time()
                        if now - last_update >= 0.2:
                            pct = int(bytes_done * 100 / img_size) if img_size > 0 else 0
                            self.progress.emit(min(pct, 99))
                            spd = bytes_done / (now - start + 1e-6)
                            remaining = img_size - bytes_done
                            eta = remaining / spd if spd > 0 else 0
                            self.speed_eta.emit(f"{human_bytes(int(spd))}/s — ETA {self._fmt_eta(eta)}")
                            self.status.emit(f"Wrote {human_bytes(bytes_done)} / {human_bytes(img_size)}")
                            last_update = now

                    # Final update
                    self.progress.emit(99)
                finally:
                    if dev:
                        dev.flush()
                        dev.close()
        finally:
            # Bring device online back
            self.status.emit("Bringing device online...")
            try:
                set_disk_offline(disk, offline=False)
            except Exception as e:
                self.status.emit(f"Warning: failed to bring device online automatically: {e}")

        img_hash_hex = h_img.hexdigest() if h_img else None
        if h_img:
            self.status.emit(f"Image {hash_alg} = {img_hash_hex}")

        if verify and not simulate:
            self._verify_device_against_image(disk, img_path, img_size, block_size, hash_alg, img_hash_hex)

        self.progress.emit(100)
        elapsed = time.time() - start
        speed = img_size / elapsed if elapsed > 0 else 0
        self.speed_eta.emit(f"{human_bytes(int(speed))}/s — Done in {self._fmt_eta(elapsed)}")
        self.status.emit("Write completed.")
        self.finished.emit({
            "mode": "WRITE",
            "status": "OK",
            "disk": disk,
            "image": img_path,
            "image_size": img_size,
            "hash_alg": hash_alg,
            "image_hash": img_hash_hex
        })

    def _verify_device_against_image(self, disk: int, img_path: str, img_size: int, block_size: int,
                                     hash_alg: Optional[str], img_hash_hex: Optional[str]):
        self.status.emit("Verifying written data (device -> hash)...")
        h_dev = hashlib.md5() if hash_alg == "MD5" else (hashlib.sha256() if hash_alg == "SHA256" else None)
        if not h_dev:
            self.status.emit("No hash selected; skipping verification.")
            return

        bytes_done = 0
        last_update = time.time()
        start = last_update
        with open(img_path, "rb", buffering=0) as fimg_src:
            dev = open_raw_device(disk, write=False)
            try:
                while bytes_done < img_size:
                    if self._cancel:
                        raise RuntimeError("Operation cancelled by user.")
                    to_read = min(block_size, img_size - bytes_done)
                    b = dev.read(to_read)
                    if not b:
                        raise RuntimeError("Unexpected end of device during verification.")
                    h_dev.update(b)
                    bytes_done += len(b)
                    now = time.time()
                    if now - last_update >= 0.3:
                        pct = int(bytes_done * 100 / img_size)
                        self.progress.emit(min(pct, 99))
                        spd = bytes_done / (now - start + 1e-6)
                        remaining = img_size - bytes_done
                        eta = remaining / spd if spd > 0 else 0
                        self.speed_eta.emit(f"{human_bytes(int(spd))}/s — Verifying ETA {self._fmt_eta(eta)}")
                        last_update = now
            finally:
                dev.close()

        dev_hash_hex = h_dev.hexdigest()
        self.status.emit(f"Device {hash_alg} = {dev_hash_hex}")
        if img_hash_hex and img_hash_hex.lower() != dev_hash_hex.lower():
            raise RuntimeError("Verification failed: device hash does not match image hash.")
        self.status.emit("Verification successful.")

    def _run_read(self):
        disk: int = self.args["disk"]
        out_path: str = self.args["image_path"]
        block_size: int = self.args["block_size"]
        hash_alg: Optional[str] = self.args.get("hash_alg")
        device_size: int = int(self.args["device_size"])

        self.status.emit(f"Preparing to READ disk #{disk} -> image")
        self.status.emit(f"Output: {out_path} (target size {human_bytes(device_size)})")
        self.progress.emit(0)

        # Take device offline for consistent read (optional, but reduces OS interference)
        self.status.emit("Taking device offline (read mode)...")
        set_disk_offline(disk, offline=True)
        set_disk_offline(disk, offline=True, read_only=True)

        h = hashlib.md5() if hash_alg == "MD5" else (hashlib.sha256() if hash_alg == "SHA256" else None)

        start = time.time()
        bytes_done = 0
        last_update = start

        try:
            dev = open_raw_device(disk, write=False)
            with open(out_path, "wb", buffering=0) as fout:
                try:
                    while bytes_done < device_size:
                        if self._cancel:
                            raise RuntimeError("Operation cancelled by user.")
                        to_read = min(block_size, device_size - bytes_done)
                        b = dev.read(to_read)
                        if not b:
                            # Some devices may short-read at end; break if no data
                            break
                        if h:
                            h.update(b)
                        fout.write(b)
                        bytes_done += len(b)

                        now = time.time()
                        if now - last_update >= 0.2:
                            pct = int(bytes_done * 100 / device_size) if device_size > 0 else 0
                            self.progress.emit(min(pct, 99))
                            spd = bytes_done / (now - start + 1e-6)
                            remaining = device_size - bytes_done
                            eta = remaining / spd if spd > 0 else 0
                            self.speed_eta.emit(f"{human_bytes(int(spd))}/s — ETA {self._fmt_eta(eta)}")
                            self.status.emit(f"Read {human_bytes(bytes_done)} / {human_bytes(device_size)}")
                            last_update = now
                finally:
                    dev.close()
        finally:
            self.status.emit("Bringing device online...")
            try:
                set_disk_offline(disk, offline=False)
            except Exception as e:
                self.status.emit(f"Warning: failed to bring device online automatically: {e}")

        self.progress.emit(100)
        elapsed = time.time() - start
        speed = bytes_done / elapsed if elapsed > 0 else 0
        self.speed_eta.emit(f"{human_bytes(int(speed))}/s — Done in {self._fmt_eta(elapsed)}")
        out_hash = h.hexdigest() if h else None
        if out_hash:
            self.status.emit(f"Output {hash_alg} = {out_hash}")
        self.status.emit("Read completed.")
        self.finished.emit({
            "mode": "READ",
            "status": "OK",
            "disk": disk,
            "image": out_path,
            "bytes": bytes_done,
            "hash_alg": hash_alg,
            "hash": out_hash
        })

    @staticmethod
    def _fmt_eta(seconds: float) -> str:
        seconds = int(seconds)
        h = seconds // 3600
        m = (seconds % 3600) // 60
        s = seconds % 60
        if h:
            return f"{h:02d}:{m:02d}:{s:02d}"
        return f"{m:02d}:{s:02d}"

# =========================
# Confirm dialog for write
# =========================

class ConfirmDialog(QDialog):
    def __init__(self, parent, disk_number: int, summary_text: str):
        super().__init__(parent)
        self.setWindowTitle("Confirm write to device")
        self.setModal(True)
        self.setMinimumWidth(560)

        layout = QVBoxLayout(self)

        info = QLabel(summary_text)
        info.setWordWrap(True)
        info.setStyleSheet("QLabel { color: #444; }")
        layout.addWidget(info)

        layout.addWidget(self._hline())

        form = QFormLayout()
        self.code_label = QLabel(f"Type exactly: WRITE-{disk_number}")
        self.code_edit = QLineEdit()
        self.code_edit.setPlaceholderText(f"WRITE-{disk_number}")
        form.addRow(self.code_label, self.code_edit)
        layout.addLayout(form)

        layout.addWidget(self._hline())

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.button(QDialogButtonBox.Ok).setText("Confirm")
        self.buttons.button(QDialogButtonBox.Cancel).setText("Cancel")
        self.buttons.accepted.connect(self._on_ok)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

    def _hline(self):
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        return line

    def _on_ok(self):
        if self.code_edit.text().strip() == self.code_label.text().split(":")[-1].strip():
            self.accept()
        else:
            QMessageBox.warning(self, "Wrong confirmation", "The text does not match. Please check and try again.")

# =========================
# Main window
# =========================

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WinDiskImage — Windows image writer/reader")
        self.resize(1060, 720)

        self.worker: Optional[ImagingWorker] = None
        self._disks: List[DiskInfo] = []

        root = QWidget()
        self.setCentralWidget(root)
        main = QVBoxLayout(root)

        # Admin banner
        self.admin_banner = QLabel("")
        self.admin_banner.setWordWrap(True)
        self.admin_banner.setStyleSheet("QLabel { background:#FFF3CD; color:#7A5E00; border:1px solid #FFECB5; padding:8px; }")
        main.addWidget(self.admin_banner)

        # Device table
        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels([
            "#", "Capacity", "Bus", "Name", "Letters", "System", "Boot", "Read-only", "Removable"
        ])
        self.table.setSelectionBehavior(self.table.SelectRows)
        self.table.setEditTriggers(self.table.NoEditTriggers)
        main.addWidget(self.table)

        # Image selectors and mode
        row1 = QHBoxLayout()
        self.mode_group = QButtonGroup(self)
        self.rb_write = QRadioButton("Write image to device")
        self.rb_read = QRadioButton("Read device to image")
        self.rb_write.setChecked(True)
        self.mode_group.addButton(self.rb_write)
        self.mode_group.addButton(self.rb_read)
        row1.addWidget(self.rb_write)
        row1.addWidget(self.rb_read)
        row1.addStretch(1)
        main.addLayout(row1)

        row2 = QHBoxLayout()
        self.image_edit = QLineEdit()
        self.image_edit.setPlaceholderText("Select an image file (.img, .bin, .iso)")
        self.browse_btn = QPushButton("Browse…")
        row2.addWidget(QLabel("Image file:"))
        row2.addWidget(self.image_edit, 3)
        row2.addWidget(self.browse_btn)
        main.addLayout(row2)

        # Options
        opts = QHBoxLayout()
        self.block_combo = QComboBox()
        self.block_combo.addItems(["1 MiB", "2 MiB", "4 MiB", "8 MiB", "16 MiB", "32 MiB"])
        self.block_combo.setCurrentText("4 MiB")

        self.hash_combo = QComboBox()
        self.hash_combo.addItems(["None", "MD5", "SHA256"])
        self.verify_check = QCheckBox("Verify after write")
        self.simulate_check = QCheckBox("Simulate write (no changes)")
        self.simulate_check.setChecked(False)

        opts.addWidget(QLabel("Block size:"))
        opts.addWidget(self.block_combo)
        opts.addWidget(QLabel("Hash:"))
        opts.addWidget(self.hash_combo)
        opts.addWidget(self.verify_check)
        opts.addWidget(self.simulate_check)
        main.addLayout(opts)

        # Buttons
        btns = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh")
        self.start_btn = QPushButton("Start")
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.elevate_btn = QPushButton("Run as Administrator")
        btns.addWidget(self.refresh_btn)
        btns.addWidget(self.start_btn)
        btns.addWidget(self.cancel_btn)
        btns.addStretch(1)
        btns.addWidget(self.elevate_btn)
        main.addLayout(btns)

        # Log and progress
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        main.addWidget(self.log)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        main.addWidget(self.progress)

        self.speed_label = QLabel("")
        main.addWidget(self.speed_label)

        # Signals
        self.refresh_btn.clicked.connect(self.load_disks)
        self.start_btn.clicked.connect(self.on_start)
        self.cancel_btn.clicked.connect(self.on_cancel)
        self.elevate_btn.clicked.connect(relaunch_as_admin)
        self.browse_btn.clicked.connect(self.on_browse)
        self.rb_write.toggled.connect(self.on_mode_change)

        self.update_admin_banner()
        self.on_mode_change()
        self.load_disks()

    # ---- UI state

    def update_admin_banner(self):
        if not is_windows():
            self.admin_banner.setText("This application works only on Windows.")
            self.elevate_btn.setEnabled(False)
            self.start_btn.setEnabled(False)
            return
        if is_admin():
            self.admin_banner.setText("Running with administrative privileges.")
            self.elevate_btn.setEnabled(False)
        else:
            self.admin_banner.setText("Administrative privileges missing. Writing to devices requires elevation.")
            self.elevate_btn.setEnabled(True)

    def set_busy(self, busy: bool):
        self.refresh_btn.setEnabled(not busy)
        self.start_btn.setEnabled(not busy)
        self.cancel_btn.setEnabled(busy)
        self.elevate_btn.setEnabled(not busy)
        self.table.setEnabled(not busy)
        self.browse_btn.setEnabled(not busy)
        self.rb_write.setEnabled(not busy)
        self.rb_read.setEnabled(not busy)
        self.hash_combo.setEnabled(not busy)
        self.verify_check.setEnabled(not busy)
        self.simulate_check.setEnabled(not busy)
        self.block_combo.setEnabled(not busy)

    def on_mode_change(self):
        if self.rb_write.isChecked():
            self.image_edit.setPlaceholderText("Select an existing image file (.img, .bin, .iso)")
            self.verify_check.setEnabled(True)
            self.simulate_check.setEnabled(True)
        else:
            self.image_edit.setPlaceholderText("Choose output image path (.img)")
            self.verify_check.setEnabled(False)
            self.simulate_check.setEnabled(False)
            self.verify_check.setChecked(False)

    # ---- Disks

    def load_disks(self):
        try:
            disks = list_disks()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            disks = []
        self._disks = disks
        self.table.setRowCount(0)
        for d in disks:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(str(d.number)))
            self.table.setItem(row, 1, QTableWidgetItem(human_bytes(d.size)))
            self.table.setItem(row, 2, QTableWidgetItem(d.bus_type))
            self.table.setItem(row, 3, QTableWidgetItem(d.friendly_name))
            self.table.setItem(row, 4, QTableWidgetItem(",".join(str(x) for x in d.letters)))
            self.table.setItem(row, 5, QTableWidgetItem("Yes" if d.is_system else "No"))
            self.table.setItem(row, 6, QTableWidgetItem("Yes" if d.is_boot else "No"))
            self.table.setItem(row, 7, QTableWidgetItem("Yes" if d.is_readonly else "No"))
            self.table.setItem(row, 8, QTableWidgetItem("Yes" if d.is_removable else "No"))

            # Dull out unsafe rows for writing
            if d.is_system or d.is_boot:
                for c in range(self.table.columnCount()):
                    item = self.table.item(row, c)
                    if item:
                        item.setForeground(Qt.gray)

        self.table.resizeColumnsToContents()

    def selected_disk(self) -> Optional[DiskInfo]:
        row = self.table.currentRow()
        if row < 0 or row >= len(self._disks):
            return None
        return self._disks[row]

    # ---- File dialogs

    def on_browse(self):
        if self.rb_write.isChecked():
            path, _ = QFileDialog.getOpenFileName(self, "Select image file", "", "Image files (*.img *.bin *.iso);;All files (*.*)")
        else:
            path, _ = QFileDialog.getSaveFileName(self, "Choose output image path", "backup.img", "Image files (*.img);;All files (*.*)")
        if path:
            self.image_edit.setText(path)

    # ---- Start action

    def on_start(self):
        d = self.selected_disk()
        if not d:
            QMessageBox.warning(self, "No device selected", "Please select a device from the table.")
            return

        write_mode = self.rb_write.isChecked()

        # Safety: forbid writing to system/boot or non-removable (unless explicitly allowed)
        if write_mode:
            if not is_admin():
                res = QMessageBox.question(
                    self, "Administrator required",
                    "Writing to devices requires administrative privileges. Restart as Administrator now?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if res == QMessageBox.Yes:
                    relaunch_as_admin()
                return
            if d.is_system or d.is_boot:
                QMessageBox.critical(self, "Blocked", "Writing to system/boot disks is not allowed.")
                return
            if not d.is_removable and d.bus_type.upper() != "USB":
                QMessageBox.critical(self, "Blocked", "Target disk is not removable/USB. Operation not allowed.")
                return

        img_path = self.image_edit.text().strip()
        if not img_path:
            QMessageBox.warning(self, "Image path missing", "Please select an image file path.")
            return

        block_size = parse_block_size(self.block_combo.currentText())
        hash_sel = self.hash_combo.currentText()
        hash_alg = None if hash_sel == "None" else hash_sel
        verify_after = self.verify_check.isChecked()
        simulate = self.simulate_check.isChecked()

        if write_mode and not os.path.exists(img_path):
            QMessageBox.warning(self, "Image not found", "Selected image file does not exist.")
            return

        if (not write_mode) and os.path.exists(img_path):
            res = QMessageBox.question(self, "Overwrite file?", f"File already exists:\n{img_path}\nOverwrite?", QMessageBox.Yes | QMessageBox.No)
            if res != QMessageBox.Yes:
                return

        if write_mode:
            # Confirm destructive write
            summary = (
                f"You are about to WRITE an image to disk #{d.number}\n"
                f"- Capacity: {human_bytes(d.size)}\n"
                f"- Bus: {d.bus_type}\n"
                f"- Name: {d.friendly_name}\n"
                f"- Image: {img_path}\n"
                f"- Block size: {self.block_combo.currentText()}\n"
                f"- Hash: {hash_sel}\n"
                f"- Verify after write: {verify_after}\n"
                f"- Simulate: {simulate}\n\n"
                "WARNING: All data on the selected device will be destroyed."
            )
            dlg = ConfirmDialog(self, d.number, summary)
            if dlg.exec() != QDialog.Accepted:
                return

        self.log.clear()
        self.progress.setValue(0)
        self.speed_label.setText("")
        self.set_busy(True)

        args = {
            "mode": "WRITE" if write_mode else "READ",
            "disk": d.number,
            "device_size": d.size,
            "image_path": img_path,
            "block_size": block_size,
            "hash_alg": hash_alg,
            "verify_after": verify_after,
            "simulate": simulate if write_mode else False
        }

        self.worker = ImagingWorker(args)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.status.connect(self.on_status)
        self.worker.speed_eta.connect(self.speed_label.setText)
        self.worker.finished.connect(self.on_finished)
        self.worker.failed.connect(self.on_failed)

        # Avvia il thread
        self.worker.start()

    def on_status(self, msg: str):
        self.log.append(msg)

    def on_cancel(self):
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.cancel_btn.setEnabled(False)
            self.log.append("Cancellation requested...")

    def on_finished(self, result: Dict[str, Any]):
        self.set_busy(False)
        self.progress.setValue(100)
        self.log.append(f"Completed: {json.dumps(result, ensure_ascii=False)}")
        if result.get("status") == "OK":
            QMessageBox.information(self, "Success", f"{result.get('mode')} operation completed successfully.")
        else:
            QMessageBox.critical(self, "Error", f"Operation failed:\n{result}")
        self.load_disks()

    def on_failed(self, err: str):
        self.set_busy(False)
        self.log.append(f"Error: {err}")
        QMessageBox.critical(self, "Error", err)


# =========================
# Avvio applicazione
# =========================

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
