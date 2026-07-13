#!/usr/bin/env python3
"""
Pardus/Linux Gelişmiş Hata Analiz Uygulaması
============================================
Bu uygulama, Pardus/Linux sistemlerindeki olası sorunları otomatik olarak tespit eder,
yapay zekâ ile analiz eder ve profesyonel hata raporları sunar.

Özellikler:
- Gerçek zamanlı sistem izleme (CPU, RAM, Disk, Ağ, Sıcaklık, GPU)
- 11 farklı kategoride derinlemesine tarama
- Groq API ile AI destekli log analizi
- HTML, PDF, Markdown, JSON rapor çıktıları
- Canlı log takibi ve anlık bildirim
- Modern koyu tema, responsive arayüz

Gereksinimler: Python 3.12+, PySide6, psutil, requests
"""

import sys
import os
import re
import json
import time
import shutil
import hashlib
import subprocess
import threading
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, Callable, Any
from enum import Enum
import traceback

# ─── PySide6 ──────────────────────────────────────────────────────────────────
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QProgressBar, QTextEdit, QTreeWidget,
    QTreeWidgetItem, QStackedWidget, QFrame, QSplitter, QLineEdit,
    QComboBox, QCheckBox, QSpinBox, QFileDialog, QMessageBox,
    QScrollArea, QGridLayout, QGroupBox, QTabWidget, QListWidget,
    QListWidgetItem, QSizePolicy, QSpacerItem, QHeaderView,
    QPlainTextEdit, QDialog, QDialogButtonBox, QToolButton,
    QButtonGroup, QRadioButton, QTextBrowser, QDoubleSpinBox
)
from PySide6.QtCore import (
    Qt, QThread, Signal, QTimer, QUrl, QDateTime, QRect,
    QPropertyAnimation, QEasingCurve, QObject, Slot
)
from PySide6.QtGui import (
    QAction, QIcon, QFont, QColor, QPalette, QPainter,
    QBrush, QPen, QLinearGradient, QFontDatabase, QTextDocument,
    QPdfWriter, QPageSize, QTextCursor, QSyntaxHighlighter,
    QTextCharFormat, QDesktopServices
)
from PySide6.QtPrintSupport import QPrinter, QPrintDialog

# ─── Harici Kütüphaneler ─────────────────────────────────────────────────────
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         SABİTLER & NUMARALANDIRICILAR                        ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class Severity(Enum):
    """Hata önem dereceleri ve renk kodları."""
    CRITICAL = ("Kritik", "#FF1744", 5)
    HIGH = ("Yüksek", "#FF9100", 4)
    MEDIUM = ("Orta", "#FFD600", 3)
    LOW = ("Düşük", "#00E676", 2)
    INFO = ("Bilgi", "#40C4FF", 1)

    def __init__(self, label: str, color: str, weight: int):
        self.label = label
        self.color = color
        self.weight = weight


class ScanCategory(Enum):
    """Tarama kategorileri."""
    KERNEL = "Kernel"
    SYSTEMD = "Systemd"
    SERVICES = "Servisler"
    PACKAGES = "Paket Sistemi"
    DISK = "Disk"
    MEMORY = "Bellek"
    CPU = "İşlemci"
    GPU = "GPU"
    NETWORK = "Ağ"
    LOGS = "Loglar"
    SECURITY = "Güvenlik"


@dataclass
class ErrorEntry:
    """
    Tespit edilen bir hatanın tüm bilgilerini tutan veri sınıfı.
    AI analizi sonrası ek alanlar doldurulur.
    """
    id: str                           # Benzersiz hata kimliği
    category: ScanCategory            # Hatanın ait olduğu kategori
    severity: Severity                # Önem derecesi
    title: str                        # Kısa başlık
    description: str                  # Detaylı açıklama
    raw_log: str                      # İlgili ham log satırları
    timestamp: datetime = field(default_factory=datetime.now)  # Oluşma zamanı
    source: str = ""                  # Log kaynağı (dosya/komut)
    possible_cause: str = ""          # Muhtemel sebep
    evidence: str = ""                # Kanıtlar
    impact: str = ""                  # Etkisi
    reproducibility: str = ""         # Tekrar üretme adımları
    solution: str = ""                # Çözüm önerileri
    confidence: float = 0.0           # AI güven puanı (%)
    related_logs: list = field(default_factory=list)  # İlişkili log satırları
    ai_analyzed: bool = False         # AI analizi yapıldı mı?
    component: str = ""               # Arızalı olabilecek bileşen

    def to_dict(self) -> dict:
        """Hatayı JSON serileştirme için sözlüğe dönüştürür."""
        return {
            "id": self.id,
            "category": self.category.value,
            "severity": self.severity.name,
            "severity_label": self.severity.label,
            "title": self.title,
            "description": self.description,
            "raw_log": self.raw_log,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "possible_cause": self.possible_cause,
            "evidence": self.evidence,
            "impact": self.impact,
            "reproducibility": self.reproducibility,
            "solution": self.solution,
            "confidence": self.confidence,
            "related_logs": self.related_logs,
            "component": self.component
        }


@dataclass
class SystemSnapshot:
    """Anlık sistem durumunu tutan veri sınıfı."""
    cpu_percent: float = 0.0
    cpu_temp: float = 0.0
    ram_percent: float = 0.0
    ram_used_gb: float = 0.0
    ram_total_gb: float = 0.0
    swap_percent: float = 0.0
    disk_percent: float = 0.0
    disk_used_gb: float = 0.0
    disk_total_gb: float = 0.0
    network_sent: float = 0.0
    network_recv: float = 0.0
    active_services: int = 0
    failed_services: int = 0
    gpu_info: str = ""
    load_avg: tuple = (0.0, 0.0, 0.0)
    uptime: str = ""
    processes: int = 0
    timestamp: datetime = field(default_factory=datetime.now)


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         YARDIMCI FONKSİYONLAR                               ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class CommandRunner:
    """
    Shell komutlarını güvenli ve kontrollü şekilde çalıştırmak için yardımcı sınıf.
    Zaman aşımı, hata yönetimi ve sudo desteği içerir.
    """

    @staticmethod
    def run(command: str, timeout: int = 15, shell: bool = True,
            sudo: bool = False) -> tuple[str, str, int]:
        """
        Komut çalıştırır ve (stdout, stderr, return_code) döndürür.
        Hata durumunda bile exception fırlatmaz, boş string döner.
        """
        try:
            if sudo and os.geteuid() != 0:
                # Grafiksel sudo arayüzü veya normal sudo dene
                command = f"pkexec {command}" if shutil.which("pkexec") else f"sudo -n {command}"
            result = subprocess.run(
                command,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=timeout,
                executable="/bin/bash"
            )
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except subprocess.TimeoutExpired:
            return "", f"Timeout: {command}", -1
        except FileNotFoundError:
            return "", f"Komut bulunamadı: {command}", -2
        except Exception as e:
            return "", str(e), -3

    @staticmethod
    def run_safe(command: str, timeout: int = 10, shell: bool = True) -> str:
        """Komut çalıştırır, sadece stdout döndürür, hataları sessizce yutar."""
        stdout, _, _ = CommandRunner.run(command, timeout, shell)
        return stdout

    @staticmethod
    def which(program: str) -> bool:
        """Programın sistem PATH'inde olup olmadığını kontrol eder."""
        return shutil.which(program) is not None


def format_bytes(bytes_val: float) -> str:
    """Byte değerini okunabilir insan formatına çevirir (KB, MB, GB, TB)."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(bytes_val) < 1024.0:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} PB"


def generate_id() -> str:
    """Benzersiz, kısa bir ID üretir (ilk 10 hex karakter)."""
    return hashlib.md5(f"{time.time()}{os.urandom(4)}".encode()).hexdigest()[:10]


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         DARK TEMA STİL DOSYASI (QSS)                        ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

DARK_THEME_QSS = """
/* ─── Global ──────────────────────────────────────────── */
* {
    font-family: "Segoe UI", "Noto Sans", "Ubuntu", sans-serif;
    font-size: 13px;
}
QMainWindow {
    background-color: #0d1117;
    color: #c9d1d9;
}
QWidget {
    background-color: transparent;
    color: #c9d1d9;
}

/* ─── ScrollBar ──────────────────────────────────────── */
QScrollBar:vertical {
    background: #161b22;
    width: 8px;
    margin: 0;
    border-radius: 4px;
}
QScrollBar::handle:vertical {
    background: #30363d;
    border-radius: 4px;
    min-height: 30px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QScrollBar:horizontal {
    background: #161b22;
    height: 8px;
    margin: 0;
    border-radius: 4px;
}
QScrollBar::handle:horizontal {
    background: #30363d;
    border-radius: 4px;
    min-width: 30px;
}

/* ─── Menu / Sidebar ─────────────────────────────────── */
QFrame#sidebar {
    background-color: #161b22;
    border-right: 1px solid #21262d;
    min-width: 220px;
    max-width: 220px;
}
QPushButton#menuBtn {
    background: transparent;
    color: #8b949e;
    border: none;
    padding: 12px 16px;
    text-align: left;
    font-size: 13px;
    border-left: 3px solid transparent;
    border-radius: 0px;
}
QPushButton#menuBtn:hover {
    background-color: #1c2128;
    color: #e6edf3;
    border-left: 3px solid #30363d;
}
QPushButton#menuBtn:checked, QPushButton#menuBtn[active="true"] {
    background-color: #1a2332;
    color: #58a6ff;
    border-left: 3px solid #58a6ff;
    font-weight: bold;
}

/* ─── Kartlar (Dashboard) ────────────────────────────── */
QFrame#card {
    background-color: #161b22;
    border: 1px solid #21262d;
    border-radius: 10px;
    padding: 16px;
}
QFrame#card:hover {
    border: 1px solid #30363d;
}
QLabel#cardTitle {
    color: #8b949e;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
}
QLabel#cardValue {
    color: #e6edf3;
    font-size: 24px;
    font-weight: bold;
}
QLabel#cardSub {
    color: #58a6ff;
    font-size: 11px;
}

/* ─── Butonlar ───────────────────────────────────────── */
QPushButton {
    background-color: #21262d;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 8px 18px;
    font-weight: 500;
}
QPushButton:hover {
    background-color: #30363d;
    border: 1px solid #58a6ff;
}
QPushButton:pressed {
    background-color: #1a2332;
}
QPushButton#primaryBtn {
    background-color: #238636;
    border: 1px solid #2ea043;
    color: #ffffff;
    font-weight: bold;
}
QPushButton#primaryBtn:hover {
    background-color: #2ea043;
}
QPushButton#dangerBtn {
    background-color: #da3633;
    border: 1px solid #f85149;
    color: #ffffff;
}
QPushButton#dangerBtn:hover {
    background-color: #f85149;
}
QPushButton#cancelBtn {
    background-color: #6e7681;
    border: 1px solid #8b949e;
    color: #ffffff;
}

/* ─── ProgressBar ────────────────────────────────────── */
QProgressBar {
    background-color: #21262d;
    border: 1px solid #30363d;
    border-radius: 6px;
    height: 8px;
    text-align: center;
    font-size: 10px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #58a6ff, stop:1 #3fb950);
    border-radius: 5px;
}

/* ─── LineEdit / ComboBox / SpinBox ──────────────────── */
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {
    background-color: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 6px 10px;
    color: #c9d1d9;
}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border: 1px solid #58a6ff;
}
QComboBox::drop-down {
    border: none;
    width: 24px;
}
QComboBox QAbstractItemView {
    background-color: #161b22;
    border: 1px solid #30363d;
    selection-background-color: #1a2332;
}

/* ─── TreeWidget / ListWidget ────────────────────────── */
QTreeWidget, QListWidget {
    background-color: #0d1117;
    border: 1px solid #21262d;
    border-radius: 6px;
    alternate-background-color: #161b22;
}
QTreeWidget::item, QListWidget::item {
    padding: 6px 8px;
    border-bottom: 1px solid #21262d;
}
QTreeWidget::item:selected, QListWidget::item:selected {
    background-color: #1a2332;
    color: #58a6ff;
}
QHeaderView::section {
    background-color: #161b22;
    color: #8b949e;
    padding: 8px;
    border: none;
    border-bottom: 1px solid #21262d;
    font-weight: bold;
}

/* ─── TabWidget ──────────────────────────────────────── */
QTabWidget::pane {
    border: 1px solid #21262d;
    background-color: #0d1117;
    border-radius: 6px;
}
QTabBar::tab {
    background-color: #161b22;
    color: #8b949e;
    padding: 10px 20px;
    border: 1px solid #21262d;
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background-color: #0d1117;
    color: #58a6ff;
    border-bottom: 2px solid #58a6ff;
}

/* ─── GroupBox ───────────────────────────────────────── */
QGroupBox {
    border: 1px solid #21262d;
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 16px;
    font-weight: bold;
    color: #8b949e;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
}

/* ─── Splitter ───────────────────────────────────────── */
QSplitter::handle {
    background-color: #21262d;
    width: 1px;
}

/* ─── ToolTip ────────────────────────────────────────── */
QToolTip {
    background-color: #1c2128;
    color: #e6edf3;
    border: 1px solid #30363d;
    padding: 6px;
    border-radius: 4px;
}
"""


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         ÇALIŞAN İŞ PARÇACIĞI SINIFLARI (WORKER)            ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class BaseWorker(QThread):
    """
    Tüm worker'lar için temel sınıf.
    Ortak sinyal mekanizması, iptal desteği ve thread-safe işlemler sağlar.
    """
    progress = Signal(int, str)    # İlerleme yüzdesi ve mesaj
    finished = Signal(object)      # İşlem sonucu (generic)
    error = Signal(str)            # Hata mesajı
    log_signal = Signal(str)       # Genel log mesajı

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._is_cancelled = False
        self._mutex = threading.Lock()

    def cancel(self):
        """Worker'ı güvenli şekilde iptal eder."""
        with self._mutex:
            self._is_cancelled = True

    def is_cancelled(self) -> bool:
        """İptal durumunu thread-safe olarak döndürür."""
        with self._mutex:
            return self._is_cancelled

    def safe_sleep(self, seconds: float, check_interval: float = 0.1) -> bool:
        """
        İptal edilebilir uyku.
        True dönerse uyku tamamlandı, False dönerse iptal edildi.
        """
        elapsed = 0.0
        while elapsed < seconds:
            if self.is_cancelled():
                return False
            time.sleep(min(check_interval, seconds - elapsed))
            elapsed += check_interval
        return True


class SystemScannerWorker(BaseWorker):
    """
    Kapsamlı sistem taraması yapan worker.
    Seçili kategorilerde paralel olmayan (tek thread) tarama gerçekleştirir.
    """

    def __init__(self, categories: Optional[list[ScanCategory]] = None,
                 parent: Optional[QObject] = None):
        super().__init__(parent)
        self.categories = categories or list(ScanCategory)
        self.errors: list[ErrorEntry] = []

    def run(self):
        """Ana tarama döngüsü."""
        try:
            total = len(self.categories)
            for idx, category in enumerate(self.categories):
                if self.is_cancelled():
                    self.progress.emit(int((idx / total) * 100), "İptal edildi.")
                    return
                self.progress.emit(
                    int((idx / total) * 100),
                    f"Taranıyor: {category.value}"
                )
                self._scan_category(category)
            self.progress.emit(100, "Tarama tamamlandı.")
            self.finished.emit(self.errors)
        except Exception as e:
            self.error.emit(f"Tarama hatası: {str(e)}")

    def _scan_category(self, category: ScanCategory):
        """Kategoriye göre ilgili tarama metodunu çağırır."""
        method_map = {
            ScanCategory.KERNEL: self._scan_kernel,
            ScanCategory.SYSTEMD: self._scan_systemd,
            ScanCategory.SERVICES: self._scan_services,
            ScanCategory.PACKAGES: self._scan_packages,
            ScanCategory.DISK: self._scan_disk,
            ScanCategory.MEMORY: self._scan_memory,
            ScanCategory.CPU: self._scan_cpu,
            ScanCategory.GPU: self._scan_gpu,
            ScanCategory.NETWORK: self._scan_network,
            ScanCategory.LOGS: self._scan_logs,
            ScanCategory.SECURITY: self._scan_security,
        }
        method = method_map.get(category)
        if method:
            try:
                method()
            except Exception as e:
                self._add_error(
                    category, Severity.MEDIUM,
                    f"Tarama hatası: {category.value}",
                    str(e), traceback.format_exc()
                )

    def _add_error(self, category: ScanCategory, severity: Severity,
                   title: str, description: str, raw_log: str = "",
                   source: str = "", component: str = ""):
        """Yeni bir ErrorEntry oluşturur ve listeye ekler."""
        self.errors.append(ErrorEntry(
            id=generate_id(),
            category=category,
            severity=severity,
            title=title,
            description=description,
            raw_log=raw_log,
            source=source,
            component=component,
        ))

    # ─── Kernel Taraması ──────────────────────────────────────────────────
    def _scan_kernel(self):
        """dmesg/journalctl üzerinde kernel hatalarını tarar."""
        dmesg_out, _, _ = CommandRunner.run(
            "dmesg -T 2>/dev/null || dmesg 2>/dev/null | tail -2000", timeout=10
        )
        if not dmesg_out:
            dmesg_out, _, _ = CommandRunner.run(
                "journalctl -k --no-pager -n 1000 2>/dev/null", timeout=10
            )

        patterns = {
            ("panic", Severity.CRITICAL): r'(?i)(kernel panic|Kernel panic)',
            ("oops", Severity.CRITICAL): r'(?i)(Oops:|BUG:)',
            ("segfault", Severity.HIGH): r'(?i)(segfault|segmentation fault)',
            ("warning", Severity.MEDIUM): r'(?i)(WARNING:|WARN)',
            ("error", Severity.HIGH): r'(?i)(error|ERROR).*(?:kernel|Kernel)',
            ("firmware", Severity.MEDIUM): r'(?i)(firmware.*fail|firmware.*error|failed to load firmware)',
            ("acpi", Severity.MEDIUM): r'(?i)(ACPI.*Error|ACPI.*Fail|AE_NOT_FOUND|AE_ALREADY_EXISTS)',
            ("pci", Severity.MEDIUM): r'(?i)(PCIe.*Error|pci.*fail|PCI.*error|BAR.*invalid)',
            ("usb", Severity.LOW): r'(?i)(usb.*fail|usb.*error|usb.*reset|device descriptor)',
            ("nvme", Severity.HIGH): r'(?i)(nvme.*fail|nvme.*error|nvme.*timeout|I/O error.*nvme)',
            ("gpu_kernel", Severity.HIGH): r'(?i)(drm.*error|GPU.*hang|nouveau.*fault|amdgpu.*error|i915.*error)',
        }

        for (subtype, sev), pattern in patterns:
            matches = re.findall(pattern, dmesg_out, re.MULTILINE)
            if matches:
                for match in matches[:5]:  # ilk 5 örnek
                    context = self._extract_context(dmesg_out, match, lines=3)
                    self._add_error(
                        ScanCategory.KERNEL, sev,
                        f"Kernel {subtype.upper()} tespit edildi",
                        f"Kernel loglarında {subtype} olayı bulundu.",
                        context, "dmesg / journalctl", f"kernel_{subtype}"
                    )

    def _extract_context(self, text: str, keyword: str, lines: int = 3) -> str:
        """Bir metin içinde anahtar kelimenin geçtiği satırı ve çevresini döndürür."""
        all_lines = text.split('\n')
        for i, line in enumerate(all_lines):
            if keyword in line:
                start = max(0, i - lines)
                end = min(len(all_lines), i + lines + 1)
                return '\n'.join(all_lines[start:end])
        return keyword

    # ─── Systemd Taraması ─────────────────────────────────────────────────
    def _scan_systemd(self):
        """Başarısız servisler, boot hataları ve restart loop'ları kontrol eder."""
        failed_out, _, _ = CommandRunner.run(
            "systemctl list-units --state=failed --no-pager --no-legend 2>/dev/null",
            timeout=10
        )
        if failed_out:
            for line in failed_out.strip().split('\n')[:20]:
                parts = line.split()
                if parts:
                    service_name = parts[0]
                    self._add_error(
                        ScanCategory.SYSTEMD, Severity.HIGH,
                        f"Başarısız servis: {service_name}",
                        f"Systemd servisi başarısız durumda: {service_name}",
                        line, "systemctl", service_name
                    )

        boot_errors, _, _ = CommandRunner.run(
            "journalctl -b --no-pager -p err..emerg 2>/dev/null | tail -100",
            timeout=10
        )
        if boot_errors:
            self._add_error(
                ScanCategory.SYSTEMD, Severity.MEDIUM,
                "Boot sırasında hatalar tespit edildi",
                "Sistem başlatılırken hata seviyesinde log kayıtları bulundu.",
                boot_errors[:2000], "journalctl -b", "boot"
            )

        restart_loop, _, _ = CommandRunner.run(
            "journalctl -b --no-pager 2>/dev/null | grep -i 'restart.*loop\\|start request repeated' | tail -20",
            timeout=10
        )
        if restart_loop:
            self._add_error(
                ScanCategory.SYSTEMD, Severity.CRITICAL,
                "Servis yeniden başlatma döngüsü tespit edildi",
                "Bir veya daha fazla servis sürekli yeniden başlatılıyor.",
                restart_loop, "journalctl", "restart_loop"
            )

    # ─── Servis Taraması ──────────────────────────────────────────────────
    def _scan_services(self):
        """Pasif, maskelenmiş servisleri listeler."""
        for state, sev, label in [
            ("failed", Severity.HIGH, "Başarısız"),
            ("inactive", Severity.MEDIUM, "Pasif"),
            ("masked", Severity.LOW, "Maskelenmiş")
        ]:
            out, _, _ = CommandRunner.run(
                f"systemctl list-units --state={state} --no-pager --no-legend 2>/dev/null | head -30",
                timeout=10
            )
            if out:
                for line in out.strip().split('\n')[:15]:
                    parts = line.split()
                    if parts:
                        svc = parts[0]
                        self._add_error(
                            ScanCategory.SERVICES, sev,
                            f"{label} servis: {svc}",
                            f"Servis {state} durumunda: {svc}",
                            line, "systemctl", svc
                        )

    # ─── Paket Sistemi Taraması ───────────────────────────────────────────
    def _scan_packages(self):
        """dpkg/rpm bozukluklarını ve eksik bağımlılıkları kontrol eder."""
        if CommandRunner.which("dpkg"):
            broken, _, rc = CommandRunner.run("dpkg --audit 2>/dev/null", timeout=15)
            if broken and rc != 0:
                self._add_error(
                    ScanCategory.PACKAGES, Severity.HIGH,
                    "Bozuk paket(ler) tespit edildi",
                    "dpkg denetimi bozuk paketler buldu.",
                    broken[:1000], "dpkg --audit", "dpkg"
                )

            deps, _, _ = CommandRunner.run("apt-get check 2>&1 | head -30", timeout=15)
            if deps and "error" in deps.lower():
                self._add_error(
                    ScanCategory.PACKAGES, Severity.HIGH,
                    "Eksik bağımlılıklar var",
                    "apt-get check bağımlılık sorunları tespit etti.",
                    deps[:1000], "apt-get check", "dependencies"
                )

        if CommandRunner.which("rpm"):
            verify, _, rc = CommandRunner.run("rpm -Va 2>/dev/null | head -30", timeout=15)
            if verify:
                self._add_error(
                    ScanCategory.PACKAGES, Severity.MEDIUM,
                    "RPM paket doğrulama sorunları",
                    "Bazı RPM paketleri değişmiş veya bozulmuş olabilir.",
                    verify[:1000], "rpm -Va", "rpm"
                )

    # ─── Disk Taraması ────────────────────────────────────────────────────
    def _scan_disk(self):
        """Disk doluluk, inode, SMART ve dosya sistemi hatalarını kontrol eder."""
        df_out, _, _ = CommandRunner.run(
            "df -h --exclude-type=tmpfs --exclude-type=devtmpfs 2>/dev/null", timeout=5
        )
        if df_out:
            for line in df_out.split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    use_percent = parts[4].replace('%', '')
                    try:
                        if int(use_percent) > 90:
                            sev = Severity.HIGH if int(use_percent) > 95 else Severity.MEDIUM
                            self._add_error(
                                ScanCategory.DISK, sev,
                                f"Disk doluluk uyarısı: {parts[5]}",
                                f"Disk kullanımı %{use_percent} seviyesinde ({parts[5]}).",
                                line, "df", parts[0]
                            )
                    except ValueError:
                        pass

        inode_out, _, _ = CommandRunner.run("df -i --exclude-type=tmpfs 2>/dev/null", timeout=5)
        if inode_out:
            for line in inode_out.split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        inode_percent = int(parts[4].replace('%', ''))
                        if inode_percent > 90:
                            self._add_error(
                                ScanCategory.DISK, Severity.MEDIUM,
                                f"Inode doluluk uyarısı: {parts[5]}",
                                f"Inode kullanımı %{inode_percent} seviyesinde.",
                                line, "df -i", parts[0]
                            )
                    except ValueError:
                        pass

        if CommandRunner.which("smartctl"):
            for disk in self._find_disks():
                smart_out, _, _ = CommandRunner.run(
                    f"smartctl -H /dev/{disk} 2>/dev/null", timeout=10, sudo=True
                )
                if smart_out and "FAILED" in smart_out:
                    self._add_error(
                        ScanCategory.DISK, Severity.CRITICAL,
                        f"SMART hatası: /dev/{disk}",
                        f"Disk sağlığı başarısız: /dev/{disk}",
                        smart_out[:500], "smartctl", f"/dev/{disk}"
                    )
                elif smart_out and "PASSED" not in smart_out and "UNKNOWN" not in smart_out:
                    self._add_error(
                        ScanCategory.DISK, Severity.LOW,
                        f"SMART uyarısı: /dev/{disk}",
                        "Disk SMART durumu belirsiz.",
                        smart_out[:300], "smartctl", f"/dev/{disk}"
                    )

        fs_errors, _, _ = CommandRunner.run(
            "dmesg -T 2>/dev/null | grep -i 'ext4.*error\\|xfs.*error\\|btrfs.*error\\|I/O error' | tail -20",
            timeout=5
        )
        if fs_errors:
            self._add_error(
                ScanCategory.DISK, Severity.CRITICAL,
                "Dosya sistemi hatası tespit edildi",
                "Kernel loglarında dosya sistemi hataları bulundu.",
                fs_errors, "dmesg", "filesystem"
            )

    def _find_disks(self) -> list[str]:
        """Fiziksel diskleri (sda, nvme0n1 vb.) bulur."""
        disks = []
        out, _, _ = CommandRunner.run("lsblk -ndo NAME,TYPE 2>/dev/null", timeout=3)
        if out:
            for line in out.split('\n'):
                parts = line.split()
                if len(parts) == 2 and parts[1] == 'disk':
                    disks.append(parts[0])
        return disks[:5]

    # ─── Bellek Taraması ──────────────────────────────────────────────────
    def _scan_memory(self):
        """RAM, Swap kullanımı ve OOM killer olaylarını kontrol eder."""
        if PSUTIL_AVAILABLE:
            mem = psutil.virtual_memory()
            swap = psutil.swap_memory()
            if mem.percent > 90:
                sev = Severity.HIGH if mem.percent > 95 else Severity.MEDIUM
                self._add_error(
                    ScanCategory.MEMORY, sev,
                    f"Yüksek RAM kullanımı: %{mem.percent:.1f}",
                    f"RAM kullanımı kritik seviyede: {format_bytes(mem.used)} / {format_bytes(mem.total)}",
                    "", "psutil", "ram"
                )
            if swap.percent > 50:
                self._add_error(
                    ScanCategory.MEMORY, Severity.MEDIUM,
                    f"Yüksek Swap kullanımı: %{swap.percent:.1f}",
                    f"Swap kullanımı yüksek: {format_bytes(swap.used)} / {format_bytes(swap.total)}",
                    "", "psutil", "swap"
                )

        oom_out = CommandRunner.run_safe(
            "dmesg -T 2>/dev/null | grep -i 'oom\\|out of memory\\|killed process' | tail -20",
            timeout=5
        )
        if not oom_out:
            oom_out = CommandRunner.run_safe(
                "journalctl -k --no-pager 2>/dev/null | grep -i 'oom\\|out of memory' | tail -20",
                timeout=5
            )
        if oom_out:
            self._add_error(
                ScanCategory.MEMORY, Severity.CRITICAL,
                "OOM Killer olayı tespit edildi!",
                "Sistem bellek yetersizliğinden proses öldürmüş.",
                oom_out, "dmesg/journalctl", "oom"
            )

    # ─── CPU Taraması ─────────────────────────────────────────────────────
    def _scan_cpu(self):
        """İşlemci yüksek kullanım, anormal yük ve sıcaklık kontrolü."""
        if PSUTIL_AVAILABLE:
            cpu_percent = psutil.cpu_percent(interval=1)
            load = psutil.getloadavg()
            cpu_count = psutil.cpu_count()
            if load[0] > cpu_count * 1.5:
                self._add_error(
                    ScanCategory.CPU, Severity.HIGH,
                    f"Anormal sistem yükü: {load[0]:.1f}",
                    f"1 dakikalık yük ortalaması CPU çekirdek sayısının 1.5 katından fazla.",
                    f"Load: {load}, CPU cores: {cpu_count}", "psutil", "cpu_load"
                )

        temp = self._get_cpu_temp()
        if temp and temp > 85:
            sev = Severity.HIGH if temp > 95 else Severity.MEDIUM
            self._add_error(
                ScanCategory.CPU, sev,
                f"Yüksek CPU sıcaklığı: {temp}°C",
                f"İşlemci sıcaklığı kritik seviyede: {temp}°C",
                "", "sensors", "cpu_temp"
            )

    def _get_cpu_temp(self) -> Optional[float]:
        """CPU sıcaklığını çeşitli yöntemlerle okur."""
        paths = [
            "/sys/class/thermal/thermal_zone0/temp",
            "/sys/class/hwmon/hwmon0/temp1_input",
        ]
        for p in paths:
            try:
                with open(p, 'r') as f:
                    val = int(f.read().strip())
                    if val > 1000:
                        return val / 1000.0
                    return float(val)
            except (IOError, ValueError):
                continue
        out = CommandRunner.run_safe(
            "sensors 2>/dev/null | grep -i 'Core 0\\|Package\\|Tctl' | head -1",
            timeout=3
        )
        if out:
            nums = re.findall(r'[\d.]+', out)
            if nums:
                return float(nums[0])
        return None

    # ─── GPU Taraması ─────────────────────────────────────────────────────
    def _scan_gpu(self):
        """GPU sürücü hataları ve reset olaylarını kontrol eder."""
        gpu_errors, _, _ = CommandRunner.run(
            "dmesg -T 2>/dev/null | grep -iE 'drm.*error|GPU.*hang|nouveau|amdgpu.*fault|i915.*error|nvidia.*error|render.*error' | tail -20",
            timeout=5
        )
        if gpu_errors:
            self._add_error(
                ScanCategory.GPU, Severity.HIGH,
                "GPU sürücü hatası tespit edildi",
                "Grafik sürücüsü veya GPU ile ilgili hatalar bulundu.",
                gpu_errors, "dmesg", "gpu_driver"
            )

        gpu_reset, _, _ = CommandRunner.run(
            "dmesg -T 2>/dev/null | grep -i 'GPU.*reset\\|drm.*reset\\|GPU.*recovery' | tail -10",
            timeout=5
        )
        if gpu_reset:
            self._add_error(
                ScanCategory.GPU, Severity.HIGH,
                "GPU sıfırlama olayı tespit edildi",
                "GPU beklenmedik şekilde sıfırlanmış.",
                gpu_reset, "dmesg", "gpu_reset"
            )

    # ─── Ağ Taraması ──────────────────────────────────────────────────────
    def _scan_network(self):
        """DNS, internet erişimi, gateway ve DHCP sorunlarını kontrol eder."""
        dns_test = CommandRunner.run_safe(
            "nslookup google.com 8.8.8.8 2>/dev/null | grep -i 'Address' | tail -1",
            timeout=5
        )
        if not dns_test or "server can't find" in dns_test.lower():
            self._add_error(
                ScanCategory.NETWORK, Severity.HIGH,
                "DNS çözümleme sorunu",
                "DNS sunucusu google.com'u çözümleyemedi.",
                dns_test or "DNS test başarısız", "nslookup", "dns"
            )

        ping_test = CommandRunner.run_safe(
            "ping -c 1 -W 2 8.8.8.8 2>/dev/null", timeout=5
        )
        if "1 received" not in ping_test and "1 packets received" not in ping_test:
            self._add_error(
                ScanCategory.NETWORK, Severity.HIGH,
                "İnternet erişimi yok",
                "8.8.8.8 adresine ping atılamadı.",
                ping_test[:200], "ping", "internet"
            )

        gateway = CommandRunner.run_safe(
            "ip route show default 2>/dev/null | awk '{print $3}' | head -1", timeout=3
        )
        if not gateway:
            self._add_error(
                ScanCategory.NETWORK, Severity.MEDIUM,
                "Varsayılan ağ geçidi bulunamadı",
                "Sistemde varsayılan route tanımlı değil.",
                "", "ip route", "gateway"
            )

        dhcp_errors, _, _ = CommandRunner.run(
            "journalctl -b --no-pager 2>/dev/null | grep -i 'dhcp.*fail\\|dhcp.*error\\|dhclient.*error' | tail -10",
            timeout=5
        )
        if dhcp_errors:
            self._add_error(
                ScanCategory.NETWORK, Severity.MEDIUM,
                "DHCP sorunu tespit edildi",
                "DHCP ile ilgili hatalar bulundu.",
                dhcp_errors, "journalctl", "dhcp"
            )

    # ─── Log Taraması ─────────────────────────────────────────────────────
    def _scan_logs(self):
        """Sistem logları, Xorg/Wayland hatalarını kontrol eder."""
        for logfile in ['/var/log/syslog', '/var/log/messages', '/var/log/kern.log']:
            if os.path.exists(logfile):
                errors_out = CommandRunner.run_safe(
                    f"grep -iE 'error|fail|critical|emergency' {logfile} 2>/dev/null | tail -50",
                    timeout=10
                )
                if errors_out:
                    self._add_error(
                        ScanCategory.LOGS, Severity.INFO,
                        f"Sistem loglarında hata kayıtları: {logfile}",
                        f"{logfile} dosyasında hata/başarısızlık kayıtları bulundu.",
                        errors_out[:1500], logfile, "system_logs"
                    )
                break

        xorg_log = "/var/log/Xorg.0.log"
        if os.path.exists(xorg_log):
            x_errors = CommandRunner.run_safe(
                f"grep -iE '\\(EE\\)|error|fail' {xorg_log} 2>/dev/null | tail -20",
                timeout=5
            )
            if x_errors:
                self._add_error(
                    ScanCategory.LOGS, Severity.MEDIUM,
                    "Xorg hata kayıtları bulundu",
                    "Xorg loglarında hata (EE) kayıtları tespit edildi.",
                    x_errors, xorg_log, "xorg"
                )

        wayland_errors = CommandRunner.run_safe(
            "journalctl -b --no-pager 2>/dev/null | grep -i 'wayland.*error' | tail -10",
            timeout=5
        )
        if wayland_errors:
            self._add_error(
                ScanCategory.LOGS, Severity.LOW,
                "Wayland hata kayıtları",
                "Wayland ile ilgili hata logları bulundu.",
                wayland_errors, "journalctl", "wayland"
            )

    # ─── Güvenlik Taraması ────────────────────────────────────────────────
    def _scan_security(self):
        """Başarısız girişler, açık portlar ve SUID dosyalarını kontrol eder."""
        failed_logins = CommandRunner.run_safe("lastb 2>/dev/null | head -20", timeout=5)
        if failed_logins:
            count = len(failed_logins.strip().split('\n'))
            if count > 5:
                self._add_error(
                    ScanCategory.SECURITY, Severity.HIGH,
                    f"Çok sayıda başarısız giriş: {count}",
                    "Sisteme çok sayıda başarısız giriş denemesi yapılmış.",
                    failed_logins[:1000], "lastb", "auth"
                )

        if CommandRunner.which("ss"):
            open_ports = CommandRunner.run_safe("ss -tlnp 2>/dev/null | head -40", timeout=5)
        else:
            open_ports = CommandRunner.run_safe("netstat -tlnp 2>/dev/null | head -40", timeout=5)

        if open_ports:
            lines = open_ports.strip().split('\n')[1:]
            if len(lines) > 15:
                self._add_error(
                    ScanCategory.SECURITY, Severity.LOW,
                    f"Çok sayıda açık port: {len(lines)}",
                    "Sistemde beklenenden fazla açık port bulunuyor.",
                    open_ports[:1500], "ss/netstat", "ports"
                )

        suid_files = CommandRunner.run_safe(
            "find / -perm -4000 -type f 2>/dev/null | grep -vE '/(snap|proc|sys)' | head -30",
            timeout=10
        )
        if suid_files:
            count = len(suid_files.strip().split('\n'))
            if count > 20:
                self._add_error(
                    ScanCategory.SECURITY, Severity.MEDIUM,
                    f"Çok sayıda SUID dosyası: {count}",
                    "Sistemde beklenenden fazla SUID biti set edilmiş dosya var.",
                    suid_files[:1000], "find", "suid"
                )


class LogMonitorWorker(BaseWorker):
    """Gerçek zamanlı journalctl takip worker'ı."""
    new_log_line = Signal(str)           # Yeni log satırı
    new_error_detected = Signal(str, str)  # (severity, message)

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self.process: Optional[subprocess.Popen] = None

    def run(self):
        """journalctl -f çıktısını satır satır okuyup analiz eder."""
        try:
            self.process = subprocess.Popen(
                ["journalctl", "-f", "--no-pager", "-n", "0"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1
            )
            for line in iter(self.process.stdout.readline, ''):
                if self.is_cancelled():
                    break
                if line.strip():
                    self.new_log_line.emit(line.strip())
                    self._check_error_line(line.strip())
            self.process.stdout.close()
            self.process.wait()
        except Exception as e:
            if not self.is_cancelled():
                self.error.emit(f"Log izleme hatası: {str(e)}")

    def _check_error_line(self, line: str):
        """Log satırında kritik anahtar kelimeler arar."""
        critical_patterns = [
            (r'(?i)error', Severity.HIGH),
            (r'(?i)fail', Severity.MEDIUM),
            (r'(?i)critical', Severity.CRITICAL),
            (r'(?i)panic', Severity.CRITICAL),
            (r'(?i)segfault', Severity.CRITICAL),
            (r'(?i)oom', Severity.CRITICAL),
            (r'(?i)timeout', Severity.MEDIUM),
        ]
        for pattern, sev in critical_patterns:
            if re.search(pattern, line):
                self.new_error_detected.emit(sev.name, line)
                break

    def cancel(self):
        """Worker'ı iptal eder ve alt süreci sonlandırır."""
        super().cancel()
        if self.process:
            try:
                self.process.terminate()
            except Exception:
                pass


class AIAnalyzerWorker(BaseWorker):
    """
    Groq API kullanarak hataları yapay zekâ ile analiz eden worker.
    Hataları gruplandırır, her grup için detaylı analiz ister.
    """
    analysis_complete = Signal(dict)

    def __init__(self, errors: list[ErrorEntry], api_key: str,
                 parent: Optional[QObject] = None):
        super().__init__(parent)
        self.errors = errors
        self.api_key = api_key
        self.model = "llama-3.1-70b-versatile"  # Groq'da kullanılacak model

    def run(self):
        """Ana AI analiz akışı."""
        if not REQUESTS_AVAILABLE:
            self.error.emit("requests kütüphanesi kurulu değil.")
            return
        if not self.api_key:
            self.error.emit("Groq API anahtarı girilmemiş.")
            return

        try:
            analyzed = self._analyze_with_ai()
            self.finished.emit(analyzed)
        except Exception as e:
            self.error.emit(f"AI analiz hatası: {str(e)}")

    def _analyze_with_ai(self) -> list[ErrorEntry]:
        """Hataları gruplandırır, her grubu AI'ya gönderir."""
        grouped = self._group_errors(self.errors)
        analyzed_errors = []
        total = len(grouped)
        for idx, (key, group) in enumerate(grouped.items()):
            if self.is_cancelled():
                break
            self.progress.emit(
                int((idx / max(total, 1)) * 100),
                f"AI analiz: {idx+1}/{total}"
            )

            representative = group[0]
            combined_logs = "\n".join([e.raw_log[:500] for e in group[:5] if e.raw_log])
            prompt = self._build_analysis_prompt(representative, combined_logs, len(group))
            response = self._call_groq_api(prompt)

            if response:
                parsed = self._parse_ai_response(response, representative)
                parsed.ai_analyzed = True
                analyzed_errors.append(parsed)
            else:
                analyzed_errors.append(representative)

            time.sleep(0.5)  # API rate limiting

        self._answer_questions(grouped)
        self.progress.emit(100, "AI analiz tamamlandı.")
        return analyzed_errors

    def _group_errors(self, errors: list[ErrorEntry]) -> dict[str, list[ErrorEntry]]:
        """Benzer hataları kategori+başlık bazında gruplandırır."""
        groups: dict[str, list[ErrorEntry]] = defaultdict(list)
        for err in errors:
            key = f"{err.category.value}_{err.severity.name}_{err.title[:50]}"
            groups[key].append(err)
        return dict(groups)

    def _build_analysis_prompt(self, error: ErrorEntry, logs: str,
                               group_size: int) -> str:
        """AI için detaylı analiz prompt'u oluşturur."""
        return f"""Sen bir Linux sistem yöneticisi ve hata analiz uzmanısın. Aşağıdaki sistem hatasını detaylı analiz et.

HATA BİLGİLERİ:
- Kategori: {error.category.value}
- Önem Derecesi: {error.severity.label}
- Başlık: {error.title}
- Açıklama: {error.description}
- Tekrar Sayısı: {group_size}

LOG KAYITLARI:
{logs[:3000]}

Lütfen aşağıdaki JSON formatında yanıt ver. SADECE JSON, başka metin yazma:
{{
    "title": "Hata başlığı",
    "description": "Detaylı açıklama",
    "possible_cause": "Muhtemel sebep",
    "evidence": "Kanıtlar",
    "impact": "Etkisi (düşük/orta/yüksek/kritik)",
    "reproducibility": "Tekrar üretme adımları",
    "solution": "Çözüm önerileri (adım adım)",
    "confidence": 85,
    "component": "Hangi bileşen arızalı olabilir?",
    "related_issues": "Daha önce benzer hata var mı?"
}}"""

    def _call_groq_api(self, prompt: str) -> Optional[str]:
        """Groq API'ye HTTP POST isteği gönderir."""
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system",
                     "content": "Sen uzman bir Linux sistem analizcisisin. Yanıtların her zaman JSON formatında olsun."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.3,
                "max_tokens": 2000,
            }
            resp = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=45
            )
            if resp.status_code == 200:
                data = resp.json()
                return data["choices"][0]["message"]["content"]
            else:
                self.log_signal.emit(f"API hatası: {resp.status_code} - {resp.text[:200]}")
                return None
        except requests.exceptions.Timeout:
            self.log_signal.emit("Groq API zaman aşımı.")
            return None
        except Exception as e:
            self.log_signal.emit(f"API çağrı hatası: {str(e)}")
            return None

    def _parse_ai_response(self, response: str, original: ErrorEntry) -> ErrorEntry:
        """AI'dan gelen JSON cevabını ErrorEntry'ye dönüştürür."""
        try:
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                original.title = data.get("title", original.title)
                original.description = data.get("description", original.description)
                original.possible_cause = data.get("possible_cause", "")
                original.evidence = data.get("evidence", "")
                original.impact = data.get("impact", "")
                original.reproducibility = data.get("reproducibility", "")
                original.solution = data.get("solution", "")
                original.confidence = float(data.get("confidence", 50))
                original.component = data.get("component", "")
        except (json.JSONDecodeError, ValueError) as e:
            self.log_signal.emit(f"AI yanıtı ayrıştırılamadı: {str(e)}")
        return original

    def _answer_questions(self, grouped: dict):
        """Ek analiz sorularını cevaplar ve log'a yazar."""
        summary_parts = []
        for group in list(grouped.values())[:5]:
            for err in group[:1]:
                summary_parts.append(
                    f"- {err.title}: {err.component or 'Bilinmiyor'}"
                )
        summary = "\n".join(summary_parts)
        self.log_signal.emit(f"\n🔍 EK ANALİZ:\n{summary}")


class ReportGeneratorWorker(BaseWorker):
    """
    Tarama sonuçlarından profesyonel rapor oluşturan worker.
    JSON, Markdown, HTML, PDF formatlarını destekler.
    """

    def __init__(self, errors: list[ErrorEntry], snapshot: SystemSnapshot,
                 output_path: str, format_type: str,
                 parent: Optional[QObject] = None):
        super().__init__(parent)
        self.errors = errors
        self.snapshot = snapshot
        self.output_path = output_path
        self.format_type = format_type  # 'json', 'markdown', 'html', 'pdf'

    def run(self):
        """Rapor oluşturma işlemini başlatır."""
        try:
            self.progress.emit(10, "Rapor oluşturuluyor...")
            if self.format_type == "json":
                self._generate_json()
            elif self.format_type == "markdown":
                self._generate_markdown()
            elif self.format_type == "html":
                self._generate_html()
            elif self.format_type == "pdf":
                self._generate_pdf()
            self.progress.emit(100, "Rapor tamamlandı.")
            self.finished.emit(self.output_path)
        except Exception as e:
            self.error.emit(f"Rapor hatası: {str(e)}")

    def _generate_json(self):
        """JSON formatında rapor oluşturur."""
        data = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_errors": len(self.errors),
                "system_snapshot": {
                    "cpu_percent": self.snapshot.cpu_percent,
                    "ram_percent": self.snapshot.ram_percent,
                    "disk_percent": self.snapshot.disk_percent,
                    "failed_services": self.snapshot.failed_services,
                }
            },
            "errors": [e.to_dict() for e in self.errors]
        }
        with open(self.output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def _generate_markdown(self):
        """Markdown formatında rapor oluşturur."""
        md = f"""# 🛡️ Pardus/Linux Hata Analiz Raporu

**Oluşturulma:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Tespit Edilen Hata:** {len(self.errors)}

---

## 📊 Sistem Durumu

| Bileşen | Değer |
|---------|-------|
| CPU Kullanımı | %{self.snapshot.cpu_percent:.1f} |
| RAM Kullanımı | %{self.snapshot.ram_percent:.1f} |
| Disk Kullanımı | %{self.snapshot.disk_percent:.1f} |
| Başarısız Servis | {self.snapshot.failed_services} |

---

## 🔍 Tespit Edilen Hatalar

"""
        for err in self.errors:
            md += f"""### [{err.severity.label}] {err.title}
- **Kategori:** {err.category.value}
- **Açıklama:** {err.description}
- **Muhtemel Sebep:** {err.possible_cause or 'Belirtilmedi'}
- **Çözüm:** {err.solution or 'Belirtilmedi'}
- **Güven Puanı:** %{err.confidence:.0f}

---
"""
        with open(self.output_path, 'w', encoding='utf-8') as f:
            f.write(md)

    def _generate_html(self):
        """HTML formatında rapor oluşturur (koyu tema)."""
        severity_colors = {
            "CRITICAL": "#FF1744", "HIGH": "#FF9100", "MEDIUM": "#FFD600",
            "LOW": "#00E676", "INFO": "#40C4FF"
        }
        error_rows = ""
        for err in self.errors:
            color = severity_colors.get(err.severity.name, "#888")
            error_rows += f"""
            <tr>
                <td><span style="background:{color};color:#000;padding:2px 8px;border-radius:4px;font-size:12px;">{err.severity.label}</span></td>
                <td>{err.category.value}</td>
                <td><strong>{err.title}</strong></td>
                <td>{err.description[:100]}</td>
                <td>{err.solution[:100] if err.solution else '-'}</td>
                <td>{err.confidence:.0f}%</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Hata Analiz Raporu</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; padding: 30px; }}
        h1 {{ color: #58a6ff; border-bottom: 2px solid #21262d; padding-bottom: 10px; }}
        .summary {{ background: #161b22; padding: 20px; border-radius: 10px; margin: 20px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th {{ background: #161b22; padding: 10px; text-align: left; border-bottom: 2px solid #21262d; }}
        td {{ padding: 10px; border-bottom: 1px solid #21262d; }}
        tr:hover {{ background: #1c2128; }}
    </style>
</head>
<body>
    <h1>🛡️ Pardus/Linux Hata Analiz Raporu</h1>
    <p>Oluşturulma: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Toplam Hata: {len(self.errors)}</p>
    <div class="summary">
        <strong>Sistem Durumu:</strong>
        CPU: %{self.snapshot.cpu_percent:.1f} |
        RAM: %{self.snapshot.ram_percent:.1f} |
        Disk: %{self.snapshot.disk_percent:.1f} |
        Başarısız Servis: {self.snapshot.failed_services}
    </div>
    <table>
        <thead><tr><th>Önem</th><th>Kategori</th><th>Başlık</th><th>Açıklama</th><th>Çözüm</th><th>Güven</th></tr></thead>
        <tbody>{error_rows}</tbody>
    </table>
</body>
</html>"""
        with open(self.output_path, 'w', encoding='utf-8') as f:
            f.write(html)

    def _generate_pdf(self):
        """PySide6 QPrinter kullanarak HTML içeriğini PDF'e dönüştürür."""
        html_content = self._get_pdf_html_content()
        printer = QPrinter(QPrinter.HighResolution)
        printer.setOutputFormat(QPrinter.PdfFormat)
        printer.setOutputFileName(self.output_path)
        printer.setPageSize(QPageSize.A4)

        doc = QTextDocument()
        doc.setHtml(html_content)
        doc.print_(printer)

    def _get_pdf_html_content(self) -> str:
        """PDF için sade, yazdırılabilir HTML içeriği."""
        error_rows = ""
        for err in self.errors:
            error_rows += f"""
            <tr>
                <td>{err.severity.label}</td>
                <td>{err.category.value}</td>
                <td>{err.title}</td>
                <td>{err.description[:150]}</td>
                <td>{err.solution[:150] if err.solution else '-'}</td>
            </tr>"""
        return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><style>
body {{ font-family: Arial; font-size: 10pt; color: #333; }}
h1 {{ color: #1a56db; }}
table {{ width: 100%; border-collapse: collapse; font-size: 9pt; }}
th {{ background: #1a56db; color: white; padding: 6px; }}
td {{ padding: 4px; border-bottom: 1px solid #ddd; }}
</style></head><body>
<h1>Pardus/Linux Hata Analiz Raporu</h1>
<p>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Hata: {len(self.errors)}</p>
<table><tr><th>Önem</th><th>Kategori</th><th>Başlık</th><th>Açıklama</th><th>Çözüm</th></tr>
{error_rows}</table></body></html>"""


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         ANA PENCERE SINIFI (MainWindow)                     ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class MainWindow(QMainWindow):
    """
    Ana uygulama penceresi.
    Tüm arayüz bileşenlerini, sayfaları ve iş mantığını yönetir.
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Pardus/Linux Hata Analiz Uygulaması v2.0")
        self.setMinimumSize(1400, 900)
        self.resize(1600, 950)

        # Durum değişkenleri
        self.current_scan_errors: list[ErrorEntry] = []
        self.system_snapshot = SystemSnapshot()
        self.scan_worker: Optional[SystemScannerWorker] = None
        self.log_monitor: Optional[LogMonitorWorker] = None
        self.ai_worker: Optional[AIAnalyzerWorker] = None
        self.report_worker: Optional[ReportGeneratorWorker] = None
        self.api_key: str = ""
        self.settings_file = Path.home() / ".pardus_analyzer_settings.json"

        self._load_settings()
        self._init_ui()
        self._start_system_monitor()
        self._apply_theme()

    def _load_settings(self):
        """Ayarları JSON dosyasından yükler."""
        try:
            if self.settings_file.exists():
                with open(self.settings_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.api_key = data.get("api_key", "")
        except Exception:
            self.api_key = ""

    def _save_settings(self):
        """Ayarları JSON dosyasına kaydeder."""
        try:
            with open(self.settings_file, 'w', encoding='utf-8') as f:
                json.dump({"api_key": self.api_key}, f, ensure_ascii=False, indent=2)
        except Exception as e:
            QMessageBox.warning(self, "Uyarı", f"Ayarlar kaydedilemedi: {e}")

    def _apply_theme(self):
        """Koyu tema stilini uygular."""
        self.setStyleSheet(DARK_THEME_QSS)

    def _init_ui(self):
        """Ana arayüz bileşenlerini oluşturur."""
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ─── Sol Menü (Sidebar) ──────────────────────────────────────────
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 12, 0, 12)
        sidebar_layout.setSpacing(2)

        logo = QLabel("🔍 Pardus Analyzer")
        logo.setStyleSheet("color:#58a6ff;font-size:16px;font-weight:bold;padding:16px;")
        sidebar_layout.addWidget(logo)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("background:#21262d;max-height:1px;margin:8px 12px;")
        sidebar_layout.addWidget(sep)

        # Menü butonları
        self.menu_buttons: dict[str, QPushButton] = {}
        self.stacked_widget = QStackedWidget()

        menu_items = [
            ("dashboard", "📊  Genel Durum"),
            ("system_info", "🖥️  Sistem Bilgileri"),
            ("scan", "🔍  Hata Tarama"),
            ("realtime_logs", "📡  Gerçek Zamanlı Loglar"),
            ("ai_analysis", "🤖  AI Analiz"),
            ("reports", "📄  Oluşturulan Raporlar"),
            ("settings", "⚙️  Ayarlar"),
        ]

        self.button_group = QButtonGroup(self)
        self.button_group.setExclusive(True)

        for key, label in menu_items:
            btn = QPushButton(label)
            btn.setObjectName("menuBtn")
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, k=key: self._switch_page(k))
            sidebar_layout.addWidget(btn)
            self.menu_buttons[key] = btn
            self.button_group.addButton(btn)

        sidebar_layout.addStretch()

        ver = QLabel("v2.0.0 | Python 3.12+")
        ver.setStyleSheet("color:#484f58;font-size:10px;padding:12px;")
        ver.setAlignment(Qt.AlignCenter)
        sidebar_layout.addWidget(ver)

        # ─── Ana içerik alanı ────────────────────────────────────────────
        content_area = QFrame()
        content_layout = QVBoxLayout(content_area)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.addWidget(self.stacked_widget)

        # Splitter ile sidebar + content
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(sidebar)
        splitter.addWidget(content_area)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setHandleWidth(1)
        main_layout.addWidget(splitter)

        # Sayfaları oluştur
        self._create_dashboard_page()
        self._create_system_info_page()
        self._create_scan_page()
        self._create_realtime_logs_page()
        self._create_ai_analysis_page()
        self._create_reports_page()
        self._create_settings_page()

        # Varsayılan sayfa
        self._switch_page("dashboard")
        self.menu_buttons["dashboard"].setChecked(True)

    def _switch_page(self, page_key: str):
        """Sol menüden seçilen sayfaya geçiş yapar."""
        page_map = {
            "dashboard": 0, "system_info": 1, "scan": 2,
            "realtime_logs": 3, "ai_analysis": 4, "reports": 5, "settings": 6
        }
        idx = page_map.get(page_key, 0)
        self.stacked_widget.setCurrentIndex(idx)

    # ═══════════════════════════════════════════════════════════════════════
    # Sayfa Oluşturma Metodları
    # ═══════════════════════════════════════════════════════════════════════

    def _create_dashboard_page(self):
        """Genel Durum sayfası - sistem durum kartları."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)

        title = QLabel("Sistem Durumu")
        title.setStyleSheet("font-size:22px;font-weight:bold;color:#e6edf3;")
        layout.addWidget(title)
        layout.addSpacing(16)

        grid = QGridLayout()
        grid.setSpacing(16)

        self.dashboard_cards: dict[str, dict[str, Any]] = {}
        card_configs = [
            ("cpu_card", "CPU", "%", "#58a6ff"),
            ("ram_card", "RAM", "%", "#3fb950"),
            ("disk_card", "Disk", "%", "#d29922"),
            ("network_card", "Ağ", "MB/s", "#a371f7"),
            ("temp_card", "Sıcaklık", "°C", "#f85149"),
            ("gpu_card", "GPU", "", "#79c0ff"),
            ("services_card", "Aktif Servis", "", "#56d364"),
            ("failed_card", "Başarısız Servis", "", "#f85149"),
        ]

        for i, (key, name, unit, color) in enumerate(card_configs):
            card = QFrame()
            card.setObjectName("card")
            card.setMinimumSize(180, 120)
            card_layout = QVBoxLayout(card)

            card_title = QLabel(name)
            card_title.setObjectName("cardTitle")
            card_value = QLabel("--")
            card_value.setObjectName("cardValue")
            card_value.setStyleSheet(f"color:{color};")
            card_sub = QLabel("")
            card_sub.setObjectName("cardSub")

            card_layout.addWidget(card_title)
            card_layout.addWidget(card_value)
            card_layout.addWidget(card_sub)
            card_layout.addStretch()

            grid.addWidget(card, i // 4, i % 4)
            self.dashboard_cards[key] = {
                "frame": card, "value": card_value, "sub": card_sub, "unit": unit
            }

        layout.addLayout(grid)
        layout.addStretch()
        self.stacked_widget.addWidget(page)

    def _create_system_info_page(self):
        """Sistem Bilgileri sayfası."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)

        title = QLabel("Sistem Bilgileri")
        title.setStyleSheet("font-size:22px;font-weight:bold;color:#e6edf3;")
        layout.addWidget(title)
        layout.addSpacing(16)

        self.sys_info_text = QTextEdit()
        self.sys_info_text.setReadOnly(True)
        self.sys_info_text.setMinimumHeight(400)
        layout.addWidget(self.sys_info_text)

        refresh_btn = QPushButton("🔄 Bilgileri Yenile")
        refresh_btn.clicked.connect(self._refresh_system_info)
        layout.addWidget(refresh_btn)
        layout.addStretch()

        self.stacked_widget.addWidget(page)

    def _create_scan_page(self):
        """Hata Tarama sayfası."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)

        title = QLabel("Hata Tarama")
        title.setStyleSheet("font-size:22px;font-weight:bold;color:#e6edf3;")
        layout.addWidget(title)
        layout.addSpacing(10)

        # Kategori seçimi
        cat_group = QGroupBox("Tarama Kategorileri")
        cat_layout = QGridLayout(cat_group)
        self.category_checks: dict[ScanCategory, QCheckBox] = {}
        for i, cat in enumerate(ScanCategory):
            cb = QCheckBox(cat.value)
            cb.setChecked(True)
            self.category_checks[cat] = cb
            cat_layout.addWidget(cb, i // 3, i % 3)
        layout.addWidget(cat_group)

        # Butonlar
        btn_layout = QHBoxLayout()
        self.scan_btn = QPushButton("🔍 Tam Tarama Başlat")
        self.scan_btn.setObjectName("primaryBtn")
        self.scan_btn.setMinimumHeight(40)
        self.scan_btn.clicked.connect(self._start_scan)

        self.cancel_scan_btn = QPushButton("⏹️ İptal")
        self.cancel_scan_btn.setObjectName("cancelBtn")
        self.cancel_scan_btn.setEnabled(False)
        self.cancel_scan_btn.clicked.connect(self._cancel_scan)

        btn_layout.addWidget(self.scan_btn)
        btn_layout.addWidget(self.cancel_scan_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # İlerleme çubuğu
        self.scan_progress = QProgressBar()
        self.scan_progress.setVisible(False)
        layout.addWidget(self.scan_progress)

        self.scan_status = QLabel("")
        self.scan_status.setStyleSheet("color:#8b949e;")
        layout.addWidget(self.scan_status)

        # Filtre ve arama
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Önem:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["Tümü", "Kritik", "Yüksek", "Orta", "Düşük", "Bilgi"])
        self.severity_filter.currentTextChanged.connect(self._apply_scan_filter)
        filter_layout.addWidget(self.severity_filter)

        filter_layout.addSpacing(20)
        filter_layout.addWidget(QLabel("Ara:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Hatalar arasında canlı arama...")
        self.search_input.textChanged.connect(self._apply_scan_filter)
        filter_layout.addWidget(self.search_input)
        filter_layout.addStretch()
        layout.addLayout(filter_layout)

        # Hata listesi
        self.error_tree = QTreeWidget()
        self.error_tree.setHeaderLabels(["Önem", "Kategori", "Başlık", "Açıklama", "Güven"])
        self.error_tree.setAlternatingRowColors(True)
        self.error_tree.setRootIsDecorated(False)
        self.error_tree.setSelectionMode(QTreeWidget.ExtendedSelection)
        self.error_tree.itemDoubleClicked.connect(self._show_error_detail)
        layout.addWidget(self.error_tree)

        self.stacked_widget.addWidget(page)

    def _create_realtime_logs_page(self):
        """Gerçek Zamanlı Loglar sayfası."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)

        title = QLabel("Gerçek Zamanlı Log İzleme")
        title.setStyleSheet("font-size:22px;font-weight:bold;color:#e6edf3;")
        layout.addWidget(title)
        layout.addSpacing(10)

        btn_layout = QHBoxLayout()
        self.start_log_btn = QPushButton("▶️ İzlemeyi Başlat")
        self.start_log_btn.setObjectName("primaryBtn")
        self.start_log_btn.clicked.connect(self._start_log_monitor)

        self.stop_log_btn = QPushButton("⏹️ Durdur")
        self.stop_log_btn.setObjectName("dangerBtn")
        self.stop_log_btn.setEnabled(False)
        self.stop_log_btn.clicked.connect(self._stop_log_monitor)

        btn_layout.addWidget(self.start_log_btn)
        btn_layout.addWidget(self.stop_log_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumBlockCount(1000)  # Bellek sınırı
        layout.addWidget(self.log_text)

        self.notification_label = QLabel("")
        self.notification_label.setStyleSheet("color:#f85149;font-weight:bold;")
        layout.addWidget(self.notification_label)

        self.stacked_widget.addWidget(page)

    def _create_ai_analysis_page(self):
        """AI Analiz sayfası."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)

        title = QLabel("Yapay Zekâ Analizi")
        title.setStyleSheet("font-size:22px;font-weight:bold;color:#e6edf3;")
        layout.addWidget(title)
        layout.addSpacing(10)

        info = QLabel("Tarama sonuçlarını Groq AI ile analiz etmek için butona tıklayın.")
        info.setStyleSheet("color:#8b949e;")
        layout.addWidget(info)

        self.ai_btn = QPushButton("🤖 AI Analizi Başlat")
        self.ai_btn.setObjectName("primaryBtn")
        self.ai_btn.setMinimumHeight(40)
        self.ai_btn.clicked.connect(self._start_ai_analysis)
        layout.addWidget(self.ai_btn)

        self.ai_progress = QProgressBar()
        self.ai_progress.setVisible(False)
        layout.addWidget(self.ai_progress)

        self.ai_status = QLabel("")
        self.ai_status.setStyleSheet("color:#8b949e;")
        layout.addWidget(self.ai_status)

        self.ai_result_tree = QTreeWidget()
        self.ai_result_tree.setHeaderLabels(["Önem", "Bileşen", "Başlık", "Çözüm", "Güven"])
        self.ai_result_tree.setAlternatingRowColors(True)
        self.ai_result_tree.setRootIsDecorated(False)
        self.ai_result_tree.itemDoubleClicked.connect(self._show_error_detail)
        layout.addWidget(self.ai_result_tree)

        self.stacked_widget.addWidget(page)

    def _create_reports_page(self):
        """Oluşturulan Raporlar sayfası."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)

        title = QLabel("Rapor Oluştur")
        title.setStyleSheet("font-size:22px;font-weight:bold;color:#e6edf3;")
        layout.addWidget(title)
        layout.addSpacing(10)

        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("Format:"))
        self.report_format = QComboBox()
        self.report_format.addItems(["HTML", "PDF", "Markdown", "JSON"])
        format_layout.addWidget(self.report_format)
        format_layout.addStretch()

        self.report_btn = QPushButton("📄 Raporu Kaydet")
        self.report_btn.setObjectName("primaryBtn")
        self.report_btn.clicked.connect(self._generate_report)
        format_layout.addWidget(self.report_btn)
        layout.addLayout(format_layout)

        layout.addStretch()
        self.stacked_widget.addWidget(page)

    def _create_settings_page(self):
        """Ayarlar sayfası."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)

        title = QLabel("Ayarlar")
        title.setStyleSheet("font-size:22px;font-weight:bold;color:#e6edf3;")
        layout.addWidget(title)
        layout.addSpacing(20)

        api_group = QGroupBox("Groq API Yapılandırması")
        api_layout = QVBoxLayout(api_group)

        api_key_layout = QHBoxLayout()
        api_key_layout.addWidget(QLabel("API Anahtarı:"))
        self.api_key_input = QLineEdit()
        self.api_key_input.setEchoMode(QLineEdit.Password)
        self.api_key_input.setText(self.api_key)
        api_key_layout.addWidget(self.api_key_input)

        show_key_btn = QPushButton("👁️")
        show_key_btn.setFixedWidth(40)
        show_key_btn.setCheckable(True)
        show_key_btn.toggled.connect(lambda checked: self.api_key_input.setEchoMode(
            QLineEdit.Normal if checked else QLineEdit.Password
        ))
        api_key_layout.addWidget(show_key_btn)
        api_layout.addLayout(api_key_layout)

        save_btn = QPushButton("💾 Kaydet")
        save_btn.clicked.connect(self._save_api_key)
        api_layout.addWidget(save_btn)
        layout.addWidget(api_group)
        layout.addStretch()

        self.stacked_widget.addWidget(page)

    # ═══════════════════════════════════════════════════════════════════════
    # Sistem İzleme
    # ═══════════════════════════════════════════════════════════════════════

    def _start_system_monitor(self):
        """Periyodik sistem bilgisi güncellemesi için timer başlatır."""
        self.monitor_timer = QTimer(self)
        self.monitor_timer.timeout.connect(self._update_dashboard)
        self.monitor_timer.start(2000)  # 2 saniyede bir
        self._update_dashboard()  # İlk güncelleme

    def _update_dashboard(self):
        """Dashboard kartlarını ve sistem anlık görüntüsünü günceller."""
        if not PSUTIL_AVAILABLE:
            return

        try:
            # CPU
            cpu = psutil.cpu_percent(interval=0.5)
            self.system_snapshot.cpu_percent = cpu
            self._set_card_value("cpu_card", f"{cpu:.1f}", "%")

            # RAM
            mem = psutil.virtual_memory()
            self.system_snapshot.ram_percent = mem.percent
            self.system_snapshot.ram_used_gb = mem.used / (1024**3)
            self.system_snapshot.ram_total_gb = mem.total / (1024**3)
            self._set_card_value("ram_card", f"{mem.percent:.1f}",
                                 f"{mem.used / (1024**3):.1f} GB / {mem.total / (1024**3):.1f} GB")

            # Disk
            disk = psutil.disk_usage('/')
            self.system_snapshot.disk_percent = disk.percent
            self.system_snapshot.disk_used_gb = disk.used / (1024**3)
            self.system_snapshot.disk_total_gb = disk.total / (1024**3)
            self._set_card_value("disk_card", f"{disk.percent:.1f}",
                                 f"{disk.used / (1024**3):.1f} GB / {disk.total / (1024**3):.1f} GB")

            # Ağ
            net = psutil.net_io_counters()
            self.system_snapshot.network_sent = net.bytes_sent / (1024**2)
            self.system_snapshot.network_recv = net.bytes_recv / (1024**2)
            self._set_card_value("network_card",
                                 f"↓{net.bytes_recv / 1024:.0f} ↑{net.bytes_sent / 1024:.0f}",
                                 "KB")

            # Sıcaklık
            temp = self._get_cpu_temp_simple()
            self.system_snapshot.cpu_temp = temp or 0
            self._set_card_value("temp_card", f"{temp:.0f}" if temp else "--", "°C")

            # GPU
            gpu_str = self._get_gpu_info_simple()
            self.system_snapshot.gpu_info = gpu_str
            self._set_card_value("gpu_card", gpu_str if gpu_str else "--", "")

            # Servisler
            active, failed = self._count_services()
            self.system_snapshot.active_services = active
            self.system_snapshot.failed_services = failed
            self._set_card_value("services_card", str(active), f"toplam {active + failed}")
            self._set_card_value("failed_card", str(failed), "başarısız")

            # Yük ortalaması
            if hasattr(psutil, 'getloadavg'):
                self.system_snapshot.load_avg = psutil.getloadavg()

        except Exception:
            pass  # Dashboard hataları sessizce geçilir

    def _set_card_value(self, key: str, value: str, sub_text: str):
        """Dashboard kartının değerini ve alt metnini ayarlar."""
        if key in self.dashboard_cards:
            self.dashboard_cards[key]["value"].setText(value)
            self.dashboard_cards[key]["sub"].setText(sub_text)

    def _get_cpu_temp_simple(self) -> Optional[float]:
        """Basit CPU sıcaklık okuması."""
        paths = [
            "/sys/class/thermal/thermal_zone0/temp",
            "/sys/class/hwmon/hwmon0/temp1_input",
        ]
        for p in paths:
            try:
                with open(p, 'r') as f:
                    val = int(f.read().strip())
                    if val > 1000:
                        return val / 1000.0
                    return float(val)
            except (IOError, ValueError):
                continue
        return None

    def _get_gpu_info_simple(self) -> str:
        """Basit GPU bilgisi (varsa)."""
        out = CommandRunner.run_safe("lspci | grep -i vga | head -1", timeout=3)
        if out:
            return out.split(':')[-1].strip()[:40]
        return ""

    def _count_services(self) -> tuple[int, int]:
        """Aktif ve başarısız servis sayısını döndürür."""
        active = 0
        failed = 0
        out, _, _ = CommandRunner.run(
            "systemctl list-units --type=service --no-pager --no-legend 2>/dev/null",
            timeout=5
        )
        if out:
            for line in out.split('\n'):
                if 'failed' in line:
                    failed += 1
                elif 'running' in line or 'active' in line:
                    active += 1
        return active, failed

    # ═══════════════════════════════════════════════════════════════════════
    # Tarama İşlemleri
    # ═══════════════════════════════════════════════════════════════════════

    def _start_scan(self):
        """Seçili kategorilerle tarama başlatır."""
        selected = [cat for cat, cb in self.category_checks.items() if cb.isChecked()]
        if not selected:
            QMessageBox.information(self, "Bilgi", "En az bir kategori seçmelisiniz.")
            return

        self.scan_btn.setEnabled(False)
        self.cancel_scan_btn.setEnabled(True)
        self.scan_progress.setVisible(True)
        self.scan_progress.setValue(0)
        self.scan_status.setText("Tarama hazırlanıyor...")
        self.error_tree.clear()
        self.current_scan_errors.clear()

        self.scan_worker = SystemScannerWorker(selected)
        self.scan_worker.progress.connect(self._on_scan_progress)
        self.scan_worker.finished.connect(self._on_scan_finished)
        self.scan_worker.error.connect(self._on_scan_error)
        self.scan_worker.start()

    def _cancel_scan(self):
        """Devam eden taramayı iptal eder."""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.cancel()
            self.scan_status.setText("İptal ediliyor...")

    def _on_scan_progress(self, percent: int, message: str):
        """Tarama ilerleme sinyali."""
        self.scan_progress.setValue(percent)
        self.scan_status.setText(message)

    def _on_scan_finished(self, errors: list[ErrorEntry]):
        """Tarama tamamlandığında çağrılır."""
        self.current_scan_errors = errors
        self.scan_btn.setEnabled(True)
        self.cancel_scan_btn.setEnabled(False)
        self.scan_progress.setVisible(False)
        self.scan_status.setText(f"Tarama tamamlandı. {len(errors)} hata tespit edildi.")
        self._populate_error_tree(errors)

    def _on_scan_error(self, error_msg: str):
        """Tarama hatası sinyali."""
        self.scan_btn.setEnabled(True)
        self.cancel_scan_btn.setEnabled(False)
        self.scan_progress.setVisible(False)
        self.scan_status.setText(f"Hata: {error_msg}")
        QMessageBox.critical(self, "Tarama Hatası", error_msg)

    def _populate_error_tree(self, errors: list[ErrorEntry]):
        """Hata listesini TreeWidget'a doldurur."""
        self.error_tree.clear()
        severity_colors = {
            Severity.CRITICAL: QColor("#FF1744"),
            Severity.HIGH: QColor("#FF9100"),
            Severity.MEDIUM: QColor("#FFD600"),
            Severity.LOW: QColor("#00E676"),
            Severity.INFO: QColor("#40C4FF"),
        }
        for err in errors:
            item = QTreeWidgetItem([
                err.severity.label,
                err.category.value,
                err.title,
                err.description[:100],
                f"{err.confidence:.0f}%" if err.ai_analyzed else "-"
            ])
            item.setData(0, Qt.UserRole, err.id)  # ID sakla
            if err.severity in severity_colors:
                item.setForeground(0, severity_colors[err.severity])
            self.error_tree.addTopLevelItem(item)

    def _apply_scan_filter(self):
        """Seçili önem derecesi ve arama metnine göre ağaçtaki öğeleri filtreler."""
        filter_text = self.severity_filter.currentText()
        search_text = self.search_input.text().lower()

        for i in range(self.error_tree.topLevelItemCount()):
            item = self.error_tree.topLevelItem(i)
            show = True

            # Önem filtresi
            if filter_text != "Tümü":
                if item.text(0) != filter_text:
                    show = False

            # Arama filtresi
            if search_text:
                row_text = f"{item.text(0)} {item.text(1)} {item.text(2)} {item.text(3)}".lower()
                if search_text not in row_text:
                    show = False

            item.setHidden(not show)

    def _show_error_detail(self, item: QTreeWidgetItem):
        """Çift tıklanan hatanın detaylarını bir dialogda gösterir."""
        error_id = item.data(0, Qt.UserRole)
        error = next((e for e in self.current_scan_errors if e.id == error_id), None)
        if not error:
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Hata Detayı")
        dialog.setMinimumSize(700, 500)
        layout = QVBoxLayout(dialog)

        text = QTextBrowser()
        html = f"""
        <h2 style="color:{error.severity.color};">[{error.severity.label}] {error.title}</h2>
        <p><b>Kategori:</b> {error.category.value}</p>
        <p><b>Açıklama:</b> {error.description}</p>
        <p><b>Muhtemel Sebep:</b> {error.possible_cause or 'Belirtilmedi'}</p>
        <p><b>Kanıt:</b> {error.evidence or 'Yok'}</p>
        <p><b>Etkisi:</b> {error.impact or 'Bilinmiyor'}</p>
        <p><b>Tekrar Üretme:</b> {error.reproducibility or 'Belirtilmedi'}</p>
        <p><b>Çözüm:</b> {error.solution or 'Öneri yok'}</p>
        <p><b>Güven Puanı:</b> %{error.confidence:.0f}</p>
        <p><b>Arızalı Bileşen:</b> {error.component or 'Tespit edilemedi'}</p>
        <hr>
        <h3>Ham Log</h3>
        <pre>{error.raw_log[:1000]}</pre>
        """
        text.setHtml(html)
        layout.addWidget(text)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(dialog.accept)
        layout.addWidget(buttons)
        dialog.exec()

    # ═══════════════════════════════════════════════════════════════════════
    # Log İzleme
    # ═══════════════════════════════════════════════════════════════════════

    def _start_log_monitor(self):
        """Gerçek zamanlı log izlemeyi başlatır."""
        self.log_monitor = LogMonitorWorker()
        self.log_monitor.new_log_line.connect(self._on_new_log_line)
        self.log_monitor.new_error_detected.connect(self._on_new_error_detected)
        self.log_monitor.error.connect(lambda msg: self.notification_label.setText(msg))
        self.log_monitor.start()

        self.start_log_btn.setEnabled(False)
        self.stop_log_btn.setEnabled(True)
        self.log_text.clear()
        self.notification_label.setText("İzleme başladı...")

    def _stop_log_monitor(self):
        """Log izlemeyi durdurur."""
        if self.log_monitor and self.log_monitor.isRunning():
            self.log_monitor.cancel()
        self.start_log_btn.setEnabled(True)
        self.stop_log_btn.setEnabled(False)
        self.notification_label.setText("İzleme durduruldu.")

    def _on_new_log_line(self, line: str):
        """Yeni log satırını metin alanına ekler."""
        self.log_text.appendPlainText(line)

    def _on_new_error_detected(self, severity: str, message: str):
        """Kritik bir log satırı tespit edildiğinde bildirim gösterir."""
        self.notification_label.setText(f"⚠️ [{severity}] {message[:150]}")

    # ═══════════════════════════════════════════════════════════════════════
    # AI Analiz
    # ═══════════════════════════════════════════════════════════════════════

    def _start_ai_analysis(self):
        """AI analizini başlatır."""
        if not self.current_scan_errors:
            QMessageBox.information(self, "Bilgi", "Önce bir tarama yapmalısınız.")
            return
        if not self.api_key:
            QMessageBox.warning(self, "API Anahtarı Eksik",
                                "Lütfen Ayarlar sayfasından Groq API anahtarınızı girin.")
            return

        self.ai_btn.setEnabled(False)
        self.ai_progress.setVisible(True)
        self.ai_progress.setValue(0)
        self.ai_status.setText("AI analizi başlatılıyor...")
        self.ai_result_tree.clear()

        self.ai_worker = AIAnalyzerWorker(self.current_scan_errors, self.api_key)
        self.ai_worker.progress.connect(self._on_ai_progress)
        self.ai_worker.finished.connect(self._on_ai_finished)
        self.ai_worker.error.connect(self._on_ai_error)
        self.ai_worker.log_signal.connect(self._on_ai_log)
        self.ai_worker.start()

    def _on_ai_progress(self, percent: int, message: str):
        self.ai_progress.setValue(percent)
        self.ai_status.setText(message)

    def _on_ai_finished(self, analyzed_errors: list[ErrorEntry]):
        self.current_scan_errors = analyzed_errors
        self.ai_btn.setEnabled(True)
        self.ai_progress.setVisible(False)
        self.ai_status.setText(f"AI analizi tamamlandı. {len(analyzed_errors)} hata analiz edildi.")

        # AI sonuçlarını ağaca ekle
        self.ai_result_tree.clear()
        for err in analyzed_errors:
            item = QTreeWidgetItem([
                err.severity.label,
                err.component or "-",
                err.title,
                err.solution[:100] if err.solution else "-",
                f"{err.confidence:.0f}%"
            ])
            item.setData(0, Qt.UserRole, err.id)
            self.ai_result_tree.addTopLevelItem(item)

        # Tarama sayfasındaki listeyi de güncelle
        self._populate_error_tree(analyzed_errors)

    def _on_ai_error(self, error_msg: str):
        self.ai_btn.setEnabled(True)
        self.ai_progress.setVisible(False)
        self.ai_status.setText(f"Hata: {error_msg}")
        QMessageBox.critical(self, "AI Analiz Hatası", error_msg)

    def _on_ai_log(self, message: str):
        self.ai_status.setText(message)

    # ═══════════════════════════════════════════════════════════════════════
    # Rapor Oluşturma
    # ═══════════════════════════════════════════════════════════════════════

    def _generate_report(self):
        """Seçilen formatta rapor oluşturur."""
        if not self.current_scan_errors:
            QMessageBox.information(self, "Bilgi", "Rapor için önce tarama yapmalısınız.")
            return

        format_map = {
            "HTML": ("html", "HTML Dosyaları (*.html)"),
            "PDF": ("pdf", "PDF Dosyaları (*.pdf)"),
            "Markdown": ("markdown", "Markdown Dosyaları (*.md)"),
            "JSON": ("json", "JSON Dosyaları (*.json)"),
        }
        fmt = self.report_format.currentText()
        ext, filter_str = format_map.get(fmt, ("html", "HTML Dosyaları (*.html)"))

        path, _ = QFileDialog.getSaveFileName(
            self, "Raporu Kaydet",
            f"hata_raporu_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}",
            filter_str
        )
        if not path:
            return

        self.report_worker = ReportGeneratorWorker(
            self.current_scan_errors, self.system_snapshot, path, ext
        )
        self.report_worker.progress.connect(
            lambda p, m: self.scan_status.setText(m)  # geçici durum mesajı
        )
        self.report_worker.finished.connect(self._on_report_finished)
        self.report_worker.error.connect(lambda e: QMessageBox.critical(self, "Rapor Hatası", e))
        self.report_worker.start()

    def _on_report_finished(self, path: str):
        QMessageBox.information(self, "Başarılı", f"Rapor kaydedildi:\n{path}")
        # İsteğe bağlı: dosyayı aç
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    # ═══════════════════════════════════════════════════════════════════════
    # Sistem Bilgileri Sayfası
    # ═══════════════════════════════════════════════════════════════════════

    def _refresh_system_info(self):
        """Sistem bilgilerini toplayıp metin alanına yazar."""
        info = []
        info.append("🏷️ İşletim Sistemi")
        info.append(CommandRunner.run_safe("cat /etc/os-release 2>/dev/null | head -5"))
        info.append("\n🖥️ Kernel")
        info.append(CommandRunner.run_safe("uname -a"))
        info.append("\n💻 Donanım")
        info.append(CommandRunner.run_safe("lscpu | grep 'Model name\\|CPU(s)'"))
        info.append(CommandRunner.run_safe("free -h"))
        info.append(CommandRunner.run_safe("lsblk -o NAME,SIZE,TYPE,MOUNTPOINT"))
        info.append("\n🎮 GPU")
        info.append(CommandRunner.run_safe("lspci | grep -iE 'vga|3d'"))
        info.append("\n🌐 Ağ")
        info.append(CommandRunner.run_safe("ip -br addr show"))
        self.sys_info_text.setPlainText("\n".join(info))

    # ═══════════════════════════════════════════════════════════════════════
    # Ayarlar
    # ═══════════════════════════════════════════════════════════════════════

    def _save_api_key(self):
        """API anahtarını kaydeder."""
        self.api_key = self.api_key_input.text().strip()
        self._save_settings()
        QMessageBox.information(self, "Kaydedildi", "API anahtarı güncellendi.")


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         UYGULAMA BAŞLANGICI                                 ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def main():
    """Uygulama giriş noktası."""
    app = QApplication(sys.argv)
    app.setApplicationName("PardusAnalyzer")
    app.setOrganizationName("PardusProject")

    # Yüksek DPI desteği
    if hasattr(Qt, "AA_EnableHighDpiScaling"):
        app.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, "AA_UseHighDpiPixmaps"):
        app.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()