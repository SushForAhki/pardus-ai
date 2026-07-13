#!/usr/bin/env python3
"""
PARDUS Yapay Zeka Destekli Hata Analiz Sistemi
================================================
Sürüm: 1.0.0
Açıklama: Bu program, sistemden otomatik olarak topladığı log ve durum bilgilerini
         Groq API aracılığıyla analiz eder, yanlış pozitifleri eler, kök neden analizi
         yapar ve profesyonel bir hata analiz raporu (AI_Report.txt) oluşturur.

Gereksinimler:
    - Python 3.8+
    - groq kütüphanesi (pip install groq)
    - GROQ_API_KEY ortam değişkeni tanımlanmış olmalı
    - Çoğu komut için root yetkisi önerilir (sudo python3 ai_analyzer.py)
"""

import subprocess
import os
import sys
import json
import logging
import shlex
import re
import textwrap
import tempfile
import shutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from collections import OrderedDict

# ---------------------------------------------------------------------------
# Üçüncü parti kütüphane kontrolü
# ---------------------------------------------------------------------------
try:
    from groq import Groq
except ImportError:
    print("HATA: 'groq' kütüphanesi yüklü değil. Lütfen şu komutu çalıştırın:")
    print("      pip install groq")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Logger yapılandırması
# ---------------------------------------------------------------------------
LOG_FORMAT = '%(asctime)s [%(levelname)s] %(name)s - %(message)s'
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler('ai_analyzer.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('PardusAI')

# ---------------------------------------------------------------------------
# Sabitler & Yapılandırma
# ---------------------------------------------------------------------------
GROQ_API_KEY = os.environ.get('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', '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')
GROQ_MODEL = 'llama-3.1-70b-versatile'  # Hızlı, ucuz ve 128K context
MAX_TOKENS_PER_CHUNK = 2800  # Her parça için yaklaşık token sınırı (güvenli tarafta)
COMMAND_TIMEOUT = 25  # saniye
MAX_WORKERS = 6       # Paralel veri toplama için iş parçacığı sayısı

if not GROQ_API_KEY:
    logger.error("GROQ_API_KEY ortam değişkeni tanımlanmamış!")
    logger.error("Lütfen şu şekilde tanımlayın: export GROQ_API_KEY='gsk_...'")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Yardımcı fonksiyonlar
# ---------------------------------------------------------------------------
def _run_command(cmd: List[str], timeout: int = COMMAND_TIMEOUT,
                 shell: bool = False, stdin: bytes = None) -> Tuple[int, str, str]:
    """
    Bir komutu güvenli şekilde çalıştırır, çıktıyı döndürür.
    Asla çökmez; hata durumunda boş çıktı ve hata mesajı döner.
    """
    try:
        if shell:
            # shell=True sadece pipe içeren karmaşık komutlar için, dikkatli kullan
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=timeout, encoding='utf-8', errors='replace'
            )
        else:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, encoding='utf-8', errors='replace',
                stdin=stdin
            )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        logger.warning(f"Komut zaman aşımı ({timeout}s): {' '.join(cmd) if isinstance(cmd, list) else cmd}")
        return -1, '', f'Timeout: komut {timeout} saniyede tamamlanamadı'
    except FileNotFoundError:
        logger.warning(f"Komut bulunamadı: {cmd[0] if isinstance(cmd, list) else cmd}")
        return -2, '', f'Komut bulunamadı: {cmd}'
    except Exception as e:
        logger.error(f"Komut çalıştırma hatası: {e}")
        return -3, '', str(e)


def is_virtual_machine() -> bool:
    """Sistemin sanal makine olup olmadığını tespit eder."""
    _, stdout, _ = _run_command(['systemd-detect-virt'], timeout=5)
    if stdout and stdout != 'none':
        return True
    # Alternatif yöntem
    _, dmi, _ = _run_command(['cat', '/sys/class/dmi/id/product_name'])
    if dmi:
        vm_keywords = ['VirtualBox', 'VMware', 'KVM', 'QEMU', 'Bochs', 'Xen']
        for kw in vm_keywords:
            if kw.lower() in dmi.lower():
                return True
    return False


def count_tokens(text: str) -> int:
    """
    Kabaca token sayısını hesaplar (kelime başına ~1.3 token).
    Daha hassas hesaplama için tiktoken kullanılabilir fakat bağımlılığı azaltmak
    için basit yaklaşım tercih edilmiştir.
    """
    return int(len(text.split()) * 1.3)


def chunk_text(text: str, max_tokens: int = MAX_TOKENS_PER_CHUNK) -> List[str]:
    """Metni token sınırına göre parçalara böler."""
    paragraphs = text.split('\n\n')
    chunks = []
    current_chunk = []
    current_token_count = 0

    for para in paragraphs:
        para_tokens = count_tokens(para)
        if current_token_count + para_tokens > max_tokens and current_chunk:
            chunks.append('\n\n'.join(current_chunk))
            current_chunk = [para]
            current_token_count = para_tokens
        else:
            current_chunk.append(para)
            current_token_count += para_tokens

    if current_chunk:
        chunks.append('\n\n'.join(current_chunk))

    return chunks


# ---------------------------------------------------------------------------
# Veri Toplama Sınıfları
# ---------------------------------------------------------------------------
class SystemInfoCollector:
    """Temel sistem bilgilerini toplar."""

    @staticmethod
    def collect() -> Dict[str, str]:
        logger.info("Sistem bilgileri toplanıyor...")
        data = OrderedDict()
        data['Analiz Zamanı'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Hostname
        _, hostname, _ = _run_command(['hostname'])
        data['Hostname'] = hostname or 'bilinmiyor'

        # Kernel
        _, kernel, _ = _run_command(['uname', '-r'])
        data['Kernel Sürümü'] = kernel or 'bilinmiyor'

        # Tam uname
        _, uname_a, _ = _run_command(['uname', '-a'])
        data['Kernel (tam)'] = uname_a or 'bilinmiyor'

        # Dağıtım bilgisi
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                os_release = f.read()
            data['OS Release'] = os_release.strip()
        else:
            _, lsb, _ = _run_command(['lsb_release', '-a'], timeout=10)
            data['OS Release'] = lsb or 'bilinmiyor'

        # CPU bilgisi
        _, cpuinfo, _ = _run_command(['lscpu'])
        data['CPU Bilgisi'] = cpuinfo or 'bilinmiyor'

        # Bellek bilgisi
        _, meminfo, _ = _run_command(['free', '-h'])
        data['Bellek Bilgisi'] = meminfo or 'bilinmiyor'

        # Swap
        _, swap, _ = _run_command(['swapon', '--show'])
        data['Swap Bilgisi'] = swap or 'Swap aktif değil'

        # Uptime ve yük ortalaması
        _, uptime, _ = _run_command(['uptime'])
        data['Uptime & Yük'] = uptime or 'bilinmiyor'

        # GPU bilgisi
        _, lspci_gpu, _ = _run_command(['lspci', '-v', '-nn'], timeout=20)
        gpu_lines = [line for line in lspci_gpu.split('\n') if 'VGA' in line or '3D' in line or 'Display' in line]
        data['GPU(lspci)'] = '\n'.join(gpu_lines) if gpu_lines else 'GPU bulunamadı'

        # BIOS / UEFI
        if os.path.isdir('/sys/firmware/efi'):
            data['Firmware Türü'] = 'UEFI'
            _, efi_vars, _ = _run_command(['efibootmgr', '-v'], timeout=10)
            data['EFI Boot Yapılandırması'] = efi_vars or 'Okunamadı'
        else:
            data['Firmware Türü'] = 'BIOS (Legacy)'

        # Anakart bilgisi
        _, dmidecode_board, _ = _run_command(['dmidecode', '-t', 'baseboard'], timeout=15)
        data['Anakart Bilgisi'] = dmidecode_board or 'Okunamadı (root gerekebilir)'

        # Disk listesi
        _, lsblk, _ = _run_command(['lsblk', '-o', 'NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,MODEL,ROTA'])
        data['Disk Listesi'] = lsblk or 'bilinmiyor'

        # Dosya sistemleri
        _, df, _ = _run_command(['df', '-hT'])
        data['Dosya Sistemleri (df)'] = df or 'bilinmiyor'

        # Inode kullanımı
        _, df_inode, _ = _run_command(['df', '-i'])
        data['Inode Kullanımı'] = df_inode or 'bilinmiyor'

        # Oturum bilgisi
        _, who, _ = _run_command(['who', '-a'])
        data['Aktif Oturumlar'] = who or 'Oturum bilgisi yok'

        # Sanal makine kontrolü
        data['Sanal Makine'] = 'Evet' if is_virtual_machine() else 'Hayır'

        return data


class ServiceAnalyzer:
    """Systemd servis durumlarını analiz eder."""

    @staticmethod
    def collect() -> Dict[str, Any]:
        logger.info("Servis durumları toplanıyor...")
        data = OrderedDict()

        # Başarısız servisler
        _, failed, _ = _run_command(['systemctl', '--failed', '--no-legend'])
        data['Başarısız Servisler (failed)'] = failed if failed else 'Başarısız servis yok'

        # Tüm birimler (sadece servisler)
        _, all_units, _ = _run_command(
            ['systemctl', 'list-units', '--type=service', '--no-legend', '--no-pager']
        )
        data['Tüm Servis Birimleri'] = all_units if all_units else 'Liste alınamadı'

        # Sadece failed state'te olanları ayrıştır
        failed_services = []
        for line in all_units.split('\n'):
            if 'failed' in line.lower():
                parts = line.split()
                if parts:
                    failed_services.append(parts[0])
        data['Ayrıştırılan Başarısız Servisler'] = failed_services if failed_services else ['Yok']

        # Maskelenmiş servisler
        _, masked, _ = _run_command(['systemctl', 'list-unit-files', '--state=masked', '--no-legend'])
        data['Maskelenmiş Servisler'] = masked if masked else 'Maskelenmiş servis yok'

        # Aktif servisler
        _, active, _ = _run_command(['systemctl', 'list-units', '--type=service', '--state=active', '--no-legend'])
        data['Aktif Servisler'] = active if active else 'Liste alınamadı'

        # Inactive (ölü) servisler - yanlış pozitifleri elemek için önemli
        _, inactive, _ = _run_command(['systemctl', 'list-units', '--type=service', '--state=inactive', '--no-legend'])
        data['Inaktif Servisler'] = inactive if inactive else 'Liste alınamadı'

        return data


class JournalCollector:
    """Journalctl loglarını toplar."""

    @staticmethod
    def collect() -> Dict[str, str]:
        logger.info("Journal logları toplanıyor...")
        data = OrderedDict()

        # Hata seviyesindeki loglar (son 1000 satır)
        _, journal_err, _ = _run_command(
            ['journalctl', '-p', 'err', '-n', '1000', '--no-pager'], timeout=30
        )
        data['Journal Hataları (err)'] = journal_err or 'Hata seviyesinde log yok'

        # Uyarı seviyesi
        _, journal_warn, _ = _run_command(
            ['journalctl', '-p', 'warning', '-n', '500', '--no-pager'], timeout=30
        )
        data['Journal Uyarıları (warning)'] = journal_warn or 'Uyarı seviyesinde log yok'

        # Bugünkü loglar
        _, journal_today, _ = _run_command(
            ['journalctl', '--since', 'today', '--no-pager'], timeout=30
        )
        data['Bugünkü Journal'] = journal_today or 'Bugün log yok'

        # Son boot logları
        _, journal_boot, _ = _run_command(
            ['journalctl', '-b', '-n', '1000', '--no-pager'], timeout=30
        )
        data['Son Boot Journal'] = journal_boot or 'Boot logu yok'

        return data


class KernelAnalyzer:
    """Kernel loglarını ve kritik hata işaretlerini toplar."""

    @staticmethod
    def collect() -> Dict[str, Any]:
        logger.info("Kernel logları toplanıyor...")
        data = OrderedDict()

        # dmesg tamamı
        _, dmesg, _ = _run_command(['dmesg', '--level=err,warn'], timeout=20)
        data['dmesg (err+warn)'] = dmesg or 'Kernel uyarısı/hatası yok'

        # Son 500 satır dmesg
        _, dmesg_tail, _ = _run_command(['dmesg', '--level=err,warn,crit,alert,emerg'], timeout=20)
        data['dmesg (critik)'] = dmesg_tail or 'Kritik kernel mesajı yok'

        # OOM Killer taraması
        oom_lines = []
        if dmesg:
            for line in dmesg.split('\n'):
                if 'oom' in line.lower() or 'out of memory' in line.lower() or 'killed process' in line.lower():
                    oom_lines.append(line)
        data['OOM Killer İzleri'] = '\n'.join(oom_lines) if oom_lines else 'OOM bulgusu yok'

        # I/O Error taraması
        io_errors = []
        if dmesg:
            for line in dmesg.split('\n'):
                if 'i/o error' in line.lower() or 'io error' in line.lower() or 'read error' in line.lower():
                    io_errors.append(line)
        data['I/O Hata İzleri'] = '\n'.join(io_errors) if io_errors else 'I/O hatası bulgusu yok'

        # Kernel Panic / Bug / Call Trace
        panic_lines = []
        for line in (dmesg + dmesg_tail).split('\n'):
            if any(kw in line.lower() for kw in ['kernel panic', 'bug:', 'call trace', 'segfault', 'general protection fault']):
                panic_lines.append(line)
        data['Kernel Panic / Bug İzleri'] = '\n'.join(panic_lines) if panic_lines else 'Kernel panic bulgusu yok'

        # USB hataları
        usb_err = []
        for line in dmesg.split('\n'):
            if 'usb' in line.lower() and ('error' in line.lower() or 'fail' in line.lower() or 'reset' in line.lower()):
                usb_err.append(line)
        data['USB Hataları'] = '\n'.join(usb_err) if usb_err else 'USB hatası bulgusu yok'

        # PCI hataları
        pci_err = []
        for line in dmesg.split('\n'):
            if 'pci' in line.lower() and ('error' in line.lower() or 'fail' in line.lower()):
                pci_err.append(line)
        data['PCI Hataları'] = '\n'.join(pci_err) if pci_err else 'PCI hatası bulgusu yok'

        # ACPI hataları
        acpi_err = []
        for line in dmesg.split('\n'):
            if 'acpi' in line.lower() and ('error' in line.lower() or 'fail' in line.lower()):
                acpi_err.append(line)
        data['ACPI Hataları'] = '\n'.join(acpi_err) if acpi_err else 'ACPI hatası bulgusu yok'

        return data


class GraphicsAnalyzer:
    """Grafik altsistemi ile ilgili bilgileri toplar."""

    @staticmethod
    def collect() -> Dict[str, str]:
        logger.info("Grafik bilgileri toplanıyor...")
        data = OrderedDict()

        # Xorg logu (varsa)
        xorg_log_paths = ['/var/log/Xorg.0.log', '/var/log/Xorg.0.log.old']
        xorg_content = ''
        for path in xorg_log_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r', errors='replace') as f:
                        # Sadece hata ve uyarı satırlarını al
                        lines = f.readlines()
                        err_lines = [l for l in lines if '(EE)' in l or '(WW)' in l]
                        xorg_content += f'--- {path} ---\n' + ''.join(err_lines[-200:]) + '\n'
                except Exception as e:
                    logger.warning(f"Xorg log okunamadı: {e}")
        data['Xorg Hataları'] = xorg_content if xorg_content else 'Xorg log bulunamadı veya hata yok'

        # Wayland bilgisi
        _, wayland, _ = _run_command(['loginctl', 'show-session', '$(loginctl | grep $(whoami) | awk \'{print $1}\')'], shell=True)
        data['Wayland Oturumu'] = wayland if wayland else 'Wayland bilgisi alınamadı'

        # OpenGL bilgisi
        _, glxinfo, _ = _run_command(['glxinfo', '-B'], timeout=10)
        data['OpenGL Bilgisi'] = glxinfo if glxinfo else 'glxinfo çalıştırılamadı (mesa-utils gerekebilir)'

        # Vulkan bilgisi
        _, vulkan, _ = _run_command(['vulkaninfo', '--summary'], timeout=10)
        data['Vulkan Bilgisi'] = vulkan if vulkan else 'vulkaninfo çalıştırılamadı'

        # GPU sürücüsü
        _, lspci_kernel, _ = _run_command(['lspci', '-k'], timeout=20)
        gpu_sections = []
        in_gpu = False
        for line in lspci_kernel.split('\n'):
            if 'VGA' in line or '3D' in line or 'Display' in line:
                in_gpu = True
            if in_gpu:
                gpu_sections.append(line)
                if line.strip() == '':
                    in_gpu = False
        data['GPU Sürücü Bilgisi'] = '\n'.join(gpu_sections) if gpu_sections else 'Bilgi alınamadı'

        return data


class NetworkAnalyzer:
    """Ağ altsistemi bilgilerini toplar."""

    @staticmethod
    def collect() -> Dict[str, str]:
        logger.info("Ağ bilgileri toplanıyor...")
        data = OrderedDict()

        # NetworkManager durumu
        _, nm_status, _ = _run_command(['systemctl', 'status', 'NetworkManager', '--no-pager', '-l'])
        data['NetworkManager Durumu'] = nm_status or 'NetworkManager bilgisi alınamadı'

        # IP adresleri
        _, ip_addr, _ = _run_command(['ip', 'addr', 'show'])
        data['IP Adresleri'] = ip_addr or 'Bilgi alınamadı'

        # DNS yapılandırması
        if os.path.exists('/etc/resolv.conf'):
            with open('/etc/resolv.conf', 'r') as f:
                data['DNS (/etc/resolv.conf)'] = f.read().strip()
        else:
            _, resolvctl, _ = _run_command(['resolvectl', 'status'])
            data['DNS (resolvectl)'] = resolvctl or 'DNS bilgisi alınamadı'

        # Wi-Fi bilgisi
        _, iwconfig, _ = _run_command(['iwconfig'], timeout=10)
        data['Wi-Fi Arayüzleri'] = iwconfig if iwconfig else 'Wi-Fi arayüzü bulunamadı'

        # Bluetooth durumu
        _, bt_status, _ = _run_command(['systemctl', 'status', 'bluetooth', '--no-pager', '-l'])
        data['Bluetooth Durumu'] = bt_status if bt_status else 'Bluetooth servisi bulunamadı'

        # SSH durumu
        _, ssh_status, _ = _run_command(['systemctl', 'status', 'sshd', '--no-pager', '-l'])
        if ssh_status == '':
            _, ssh_status, _ = _run_command(['systemctl', 'status', 'ssh', '--no-pager', '-l'])
        data['SSH Durumu'] = ssh_status if ssh_status else 'SSH servisi aktif değil veya bulunamadı'

        # Firewall (iptables kuralları - root ile)
        _, iptables, _ = _run_command(['iptables', '-L', '-n', '--line-numbers'], timeout=10)
        data['iptables Kuralları'] = iptables if iptables else 'iptables kuralları alınamadı (root gerekebilir)'

        # nftables
        _, nft, _ = _run_command(['nft', 'list', 'ruleset'], timeout=10)
        data['nftables Kuralları'] = nft if nft else 'nftables kuralları alınamadı'

        return data


class DiskAnalyzer:
    """Disk sağlığı ve depolama bilgilerini toplar."""

    @staticmethod
    def collect() -> Dict[str, str]:
        logger.info("Disk bilgileri toplanıyor...")
        data = OrderedDict()

        # SMART verisi - tüm diskler için
        _, lsblk_devs, _ = _run_command(['lsblk', '-nd', '-o', 'NAME'])
        smart_data = ''
        for dev in lsblk_devs.split('\n'):
            dev = dev.strip()
            if not dev:
                continue
            dev_path = f'/dev/{dev}'
            _, smart_out, _ = _run_command(['smartctl', '-a', dev_path], timeout=15)
            if smart_out and 'SMART support is: Available' in smart_out:
                smart_data += f'\n=== SMART {dev_path} ===\n'
                # Sadece önemli kısımları al: hata sayısı, sağlık durumu, sıcaklık
                important_lines = []
                capture = False
                for line in smart_out.split('\n'):
                    if any(kw in line.lower() for kw in ['smart overall-health', 'smart error log',
                                                         'reallocated', 'pending sector',
                                                         'uncorrectable', 'wear level',
                                                         'media wearout', 'temperature',
                                                         'power on hours', 'total lbas written']):
                        capture = True
                    if capture and line.strip() == '':
                        capture = False
                    if capture and line.strip():
                        important_lines.append(line)
                smart_data += '\n'.join(important_lines[:30])
        data['SMART Bilgisi'] = smart_data if smart_data else 'SMART verisi alınamadı (root gerekebilir)'

        # Dosya sistemi hata kontrolü (dmesg'den)
        _, dmesg_fs, _ = _run_command(['dmesg', '--level=err,warn'], timeout=20)
        fs_errors = []
        for line in dmesg_fs.split('\n'):
            if any(fs in line.lower() for fs in ['ext4', 'btrfs', 'xfs', 'filesystem', 'fs error']):
                fs_errors.append(line)
        data['Dosya Sistemi Hataları (dmesg)'] = '\n'.join(fs_errors) if fs_errors else 'Dosya sistemi hatası bulgusu yok'

        # Mount durumu
        _, mount, _ = _run_command(['mount'])
        data['Mount Bilgisi'] = mount or 'Bilgi alınamadı'

        # Disk kullanım oranı (%)
        _, df_h, _ = _run_command(['df', '-h'])
        data['Disk Kullanım Oranı'] = df_h or 'Bilgi alınamadı'

        return data


class PackageAnalyzer:
    """Paket yöneticisi durumunu kontrol eder."""

    @staticmethod
    def collect() -> Dict[str, str]:
        logger.info("Paket sistemi kontrol ediliyor...")
        data = OrderedDict()

        # Kırık paketler
        _, broken, _ = _run_command(['apt-get', 'check'], timeout=30)
        data['Kırık Paketler (apt-get check)'] = broken if broken else 'Kırık paket bulunamadı'

        # dpkg durumu
        _, dpkg_audit, _ = _run_command(['dpkg', '--audit'], timeout=20)
        data['dpkg Denetim'] = dpkg_audit if dpkg_audit else 'dpkg denetimi temiz'

        # Bekleyen yapılandırmalar
        _, pending, _ = _run_command(['dpkg', '--configure', '-a'], timeout=10)  # sadece kontrol et, gerçekte çalıştırma
        data['Bekleyen dpkg Yapılandırması'] = 'Tamam' if not pending else pending

        # Son APT güncelleme durumu
        if os.path.exists('/var/log/apt/history.log'):
            with open('/var/log/apt/history.log', 'r') as f:
                lines = f.readlines()
                data['Son APT İşlemleri'] = ''.join(lines[-50:])
        else:
            data['Son APT İşlemleri'] = 'APT log bulunamadı'

        # Repository listesi
        _, repos, _ = _run_command(['grep', '-r', '^deb', '/etc/apt/sources.list', '/etc/apt/sources.list.d/'])
        data['Aktif Repolar'] = repos if repos else 'Repository bilgisi alınamadı'

        return data


class SecurityAnalyzer:
    """Güvenlik loglarını ve durumlarını toplar."""

    @staticmethod
    def collect() -> Dict[str, str]:
        logger.info("Güvenlik bilgileri toplanıyor...")
        data = OrderedDict()

        # Başarısız giriş denemeleri
        _, failed_logins, _ = _run_command(
            ['grep', '-i', 'failed', '/var/log/auth.log'], timeout=10
        )
        if not failed_logins:
            _, failed_logins, _ = _run_command(['journalctl', '-u', 'sshd', '--no-pager', '-n', '100'])
        data['Başarısız Giriş Denemeleri'] = failed_logins[-2000:] if failed_logins else 'Kayıt bulunamadı'

        # Sudo kullanımı
        _, sudo_log, _ = _run_command(
            ['grep', 'sudo', '/var/log/auth.log'], timeout=10
        )
        data['Sudo Kullanımı'] = sudo_log[-1000:] if sudo_log else 'Sudo kaydı bulunamadı'

        # AppArmor durumu
        _, apparmor, _ = _run_command(['aa-status'], timeout=10)
        data['AppArmor Durumu'] = apparmor if apparmor else 'AppArmor bilgisi alınamadı'

        # SELinux durumu
        if os.path.exists('/usr/sbin/sestatus'):
            _, selinux, _ = _run_command(['sestatus'], timeout=5)
            data['SELinux Durumu'] = selinux if selinux else 'SELinux aktif değil'
        else:
            data['SELinux Durumu'] = 'SELinux yüklü değil'

        # Permission denied hataları (son 100)
        _, perm_denied, _ = _run_command(['dmesg', '--level=err'], timeout=10)
        pd_lines = [l for l in perm_denied.split('\n') if 'permission denied' in l.lower()]
        data['Permission Denied Hataları'] = '\n'.join(pd_lines[:50]) if pd_lines else 'Bulgu yok'

        return data


class PerformanceAnalyzer:
    """Performans metriklerini toplar."""

    @staticmethod
    def collect() -> Dict[str, str]:
        logger.info("Performans metrikleri toplanıyor...")
        data = OrderedDict()

        # En çok bellek kullanan işlemler
        _, top_mem, _ = _run_command(
            ['ps', 'aux', '--sort=-%mem'], timeout=10
        )
        top_mem_lines = '\n'.join(top_mem.split('\n')[:15]) if top_mem else ''
        data['En Çok Bellek Kullanan İşlemler'] = top_mem_lines or 'Bilgi alınamadı'

        # En çok CPU kullanan işlemler
        _, top_cpu, _ = _run_command(
            ['ps', 'aux', '--sort=-%cpu'], timeout=10
        )
        top_cpu_lines = '\n'.join(top_cpu.split('\n')[:15]) if top_cpu else ''
        data['En Çok CPU Kullanan İşlemler'] = top_cpu_lines or 'Bilgi alınamadı'

        # CPU sıcaklığı
        _, sensors, _ = _run_command(['sensors'], timeout=10)
        data['Sıcaklık Sensörleri'] = sensors if sensors else 'Sensör bilgisi alınamadı (lm-sensors gerekebilir)'

        # Disk IO istatistiği
        _, iostat, _ = _run_command(['iostat', '-x', '1', '2'], timeout=15)
        data['Disk IO İstatistiği'] = iostat if iostat else 'iostat bulunamadı (sysstat gerekebilir)'

        # İşlem sayısı
        _, ps_count, _ = _run_command(['ps', 'aux'], timeout=10)
        process_count = len(ps_count.split('\n')) - 1 if ps_count else 0
        data['Toplam İşlem Sayısı'] = str(process_count)

        return data


# ---------------------------------------------------------------------------
# Groq API Entegrasyonu
# ---------------------------------------------------------------------------
class GroqAnalyzer:
    """Groq API ile yapay zeka analizini yönetir."""

    def __init__(self, api_key: str, model: str = GROQ_MODEL):
        self.client = Groq(api_key=api_key)
        self.model = model
        self.analysis_result = {}

    def analyze_chunk(self, chunk_text: str, chunk_num: int, total: int) -> str:
        """
        Tek bir log parçasını analiz eder ve özet çıkarır.
        """
        system_prompt = """Sen kıdemli bir Linux Sistem Mühendisi ve Siber Güvenlik Analistisin.
        Görevin, verilen sistem loglarını analiz edip şunları belirlemek:
        - Gerçek hata mı, normal davranış mı, uyarı mı?
        - Yanlış pozitif olabilir mi?
        - Performansı etkiler mi?
        - Güvenlik riski var mı?
        - Tekrar ediyor mu?
        - Kök neden ne olabilir?

        Lütfen bulgularını JSON formatında döndür:
        {
            "findings": [
                {
                    "title": "başlık",
                    "severity": "critical|medium|low|normal",
                    "confidence": 0-100,
                    "description": "açıklama",
                    "root_cause": "kök neden tahmini",
                    "affected_component": "etkilenen bileşen",
                    "recommendation": "çözüm önerisi"
                }
            ],
            "summary": "bu parçanın genel özeti"
        }
        Sadece JSON döndür, başka metin ekleme. JSON'u ```json ... ``` içine alma, doğrudan JSON ver."""

        user_prompt = f"""Aşağıdaki sistem log parçasını analiz et (Parça {chunk_num}/{total}):
        {chunk_text[:8000]}
Lütfen yukarıdaki talimatlara göre JSON formatında yanıt ver."""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.2,
                max_tokens=1500,
                response_format={"type": "json_object"}  # JSON modu
            )
            result = response.choices[0].message.content.strip()
            logger.info(f"Parça {chunk_num}/{total} analiz edildi.")
            return result
        except Exception as e:
            logger.error(f"Groq API hatası (parça {chunk_num}): {e}")
            return json.dumps({
                "findings": [],
                "summary": f"API hatası: {str(e)}"
            })

    def final_analysis(self, all_summaries: str, system_info: str) -> str:
        """
        Tüm özetleri birleştirip nihai analizi yapar ve rapor metnini üretir.
        """
        system_prompt = """Sen kıdemli bir Linux Sistem Mühendisi, SRE ve Siber Güvenlik Analistisin.
        Elinde bir Linux sistemin tüm log özetleri ve sistem bilgisi var.
        Görevin:
        1. Tüm bulguları ilişkilendir, aynı kök nedene işaret edenleri birleştir.
        2. Yanlış pozitifleri ele (oneshot servisler, timer'lar, VM uyarıları, beklenen mesajlar).
        3. Kritik, orta ve düşük öncelikli sorunları sınıflandır.
        4. Genel sistem sağlık puanı ver (0-100).
        5. Öncelikli yapılması gerekenleri sırala.

        Raporu aşağıdaki formatta düz metin olarak üret:

        ==================================================
        PARDUS YAPAY ZEKA DESTEKLİ HATA ANALİZ RAPORU
        =================================================

        Sistem Özeti:
        ...

        Kritik Hatalar:
        ...

        Orta Seviye Sorunlar:
        ...

        Düşük Öncelikli Sorunlar:
        ...

        Normal Davranışlar:
        ...

        Servis Analizi:
        ...

        Kernel Analizi:
        ...

        Grafik Analizi:
        ...

        Ağ Analizi:
        ...

        Disk Analizi:
        ...

        Performans Analizi:
        ...

        Güvenlik Analizi:
        ...

        Yapay Zekâ Yorumu:
        ...

        Genel Sistem Sağlık Puanı: X/100

        Öncelikli Yapılması Gerekenler:
        ...

        Sonuç:
        ...

        Not: Emin olmadığın konularda bunu belirt. Asla bilgi uydurma.
        """

        user_prompt = f"""Sistem Bilgisi Özeti:
{system_info[:2000]}

Tüm Log Parçalarının Analiz Özetleri:
{all_summaries[:12000]}

Lütfen yukarıdaki formata uygun kapsamlı bir rapor oluştur."""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.3,
                max_tokens=3500,
            )
            final_report = response.choices[0].message.content.strip()
            logger.info("Nihai rapor oluşturuldu.")
            return final_report
        except Exception as e:
            logger.error(f"Nihai analiz API hatası: {e}")
            return f"Rapor oluşturulamadı: {str(e)}"


# ---------------------------------------------------------------------------
# Veri Toplayıcı ve Yönetici
# ---------------------------------------------------------------------------
class DataAggregator:
    """Tüm veri toplama işlemlerini yönetir ve birleştirir."""

    def __init__(self):
        self.collectors = OrderedDict([
            ('system_info', SystemInfoCollector()),
            ('services', ServiceAnalyzer()),
            ('journal', JournalCollector()),
            ('kernel', KernelAnalyzer()),
            ('graphics', GraphicsAnalyzer()),
            ('network', NetworkAnalyzer()),
            ('disk', DiskAnalyzer()),
            ('packages', PackageAnalyzer()),
            ('security', SecurityAnalyzer()),
            ('performance', PerformanceAnalyzer()),
        ])
        self.raw_data = OrderedDict()

    def collect_all(self) -> OrderedDict:
        """Paralel olarak tüm verileri toplar."""
        logger.info("Tüm veriler toplanıyor (paralel)...")
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_section = {
                executor.submit(collector.collect): section
                for section, collector in self.collectors.items()
            }
            for future in as_completed(future_to_section):
                section = future_to_section[future]
                try:
                    self.raw_data[section] = future.result(timeout=COMMAND_TIMEOUT + 10)
                except Exception as e:
                    logger.error(f"Veri toplama hatası ({section}): {e}")
                    self.raw_data[section] = {'error': str(e)}
        return self.raw_data

    def prepare_analysis_text(self) -> str:
        """Toplanan verileri analiz için düz metin haline getirir."""
        text_parts = []
        for section, data in self.raw_data.items():
            text_parts.append(f"\n{'='*60}\n{section.upper()}\n{'='*60}")
            if isinstance(data, dict):
                for key, value in data.items():
                    text_parts.append(f"\n--- {key} ---")
                    text_parts.append(str(value)[:3000])  # Her alt bölümü sınırla
            else:
                text_parts.append(str(data)[:5000])
        return '\n'.join(text_parts)

    def save_raw_data(self, filename: str = 'raw_data.json'):
        """Ham verileri JSON olarak kaydeder (hata ayıklama için)."""
        try:
            # JSON serileştirme için dict'i dönüştür
            serializable = {}
            for section, data in self.raw_data.items():
                if isinstance(data, dict):
                    serializable[section] = data
                else:
                    serializable[section] = str(data)
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(serializable, f, indent=2, ensure_ascii=False, default=str)
            logger.info(f"Ham veriler {filename} dosyasına kaydedildi.")
        except Exception as e:
            logger.warning(f"Ham veri kaydedilemedi: {e}")


# ---------------------------------------------------------------------------
# Rapor Üretici
# ---------------------------------------------------------------------------
class ReportGenerator:
    """Nihai raporu dosyaya yazar."""

    @staticmethod
    def generate(final_report: str, filename: str = 'AI_Report.txt'):
        """Raporu UTF-8 dosyası olarak kaydeder."""
        header = f"""==================================================
PARDUS YAPAY ZEKA DESTEKLİ HATA ANALİZ RAPORU
==================================================
Oluşturulma Tarihi: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Analiz Modeli: {GROQ_MODEL}
==================================================

"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(header)
                f.write(final_report)
                f.write('\n\n')
                f.write('='*50 + '\n')
                f.write('Rapor Sonu\n')
                f.write('='*50 + '\n')
            logger.info(f"Rapor başarıyla oluşturuldu: {filename}")
            print(f"\n✅ Rapor oluşturuldu: {filename}")
            return True
        except Exception as e:
            logger.error(f"Rapor yazılamadı: {e}")
            return False


# ---------------------------------------------------------------------------
# Ana Program
# ---------------------------------------------------------------------------
def main():
    """Ana akış."""
    print("="*60)
    print("  PARDUS Yapay Zeka Destekli Hata Analiz Sistemi")
    print("="*60)
    print()

    # Root yetkisi kontrolü (opsiyonel uyarı)
    if os.geteuid() != 0:
        logger.warning("Program root olarak çalıştırılmıyor. Bazı bilgiler eksik olabilir.")
        logger.warning("Tam analiz için: sudo python3 ai_analyzer.py")
        print("⚠️  Uyarı: Root yetkisi olmadan bazı loglar ve SMART verileri alınamaz.")
        print()

    # Adım 1: Veri toplama
    print("📊 Adım 1/4: Sistem verileri toplanıyor...")
    aggregator = DataAggregator()
    raw_data = aggregator.collect_all()
    aggregator.save_raw_data()

    # Adım 2: Analiz metnini hazırla ve parçala
    print("📝 Adım 2/4: Veriler analiz için hazırlanıyor...")
    full_text = aggregator.prepare_analysis_text()
    total_tokens = count_tokens(full_text)
    logger.info(f"Toplam veri boyutu: ~{total_tokens} token, {len(full_text)} karakter")

    chunks = chunk_text(full_text)
    logger.info(f"Veri {len(chunks)} parçaya bölündü.")

    # Adım 3: Groq API ile analiz
    print(f"🤖 Adım 3/4: Groq API ile analiz yapılıyor ({len(chunks)} parça)...")
    groq = GroqAnalyzer(api_key=GROQ_API_KEY, model=GROQ_MODEL)
    summaries = []
    all_findings = []

    for i, chunk in enumerate(chunks, 1):
        print(f"   Parça {i}/{len(chunks)} analiz ediliyor...")
        result_json = groq.analyze_chunk(chunk, i, len(chunks))
        try:
            result_obj = json.loads(result_json)
            summaries.append(result_obj.get('summary', ''))
            all_findings.extend(result_obj.get('findings', []))
        except json.JSONDecodeError:
            logger.warning(f"Parça {i} JSON ayrıştırma hatası, ham metin kullanılıyor.")
            summaries.append(result_json[:500])

    # Tüm özetleri birleştir
    combined_summaries = '\n\n'.join(summaries)

    # Sistem bilgisi özetini çıkar
    system_info_text = ''
    if 'system_info' in raw_data and isinstance(raw_data['system_info'], dict):
        si = raw_data['system_info']
        system_info_text = f"""
Hostname: {si.get('Hostname', 'N/A')}
Kernel: {si.get('Kernel Sürümü', 'N/A')}
OS: {si.get('OS Release', 'N/A')[:200]}
CPU: {si.get('CPU Bilgisi', 'N/A')[:200]}
Bellek: {si.get('Bellek Bilgisi', 'N/A')[:200]}
Uptime: {si.get('Uptime & Yük', 'N/A')}
Sanal Makine: {si.get('Sanal Makine', 'N/A')}
"""

    # Ara bulguları JSON olarak kaydet
    with open('findings_intermediate.json', 'w', encoding='utf-8') as f:
        json.dump(all_findings, f, indent=2, ensure_ascii=False, default=str)
    logger.info("Ara bulgular findings_intermediate.json dosyasına kaydedildi.")

    # Nihai analiz
    print("🧠 Nihai rapor oluşturuluyor...")
    final_report = groq.final_analysis(combined_summaries, system_info_text)

    # Adım 4: Raporu kaydet
    print("📄 Adım 4/4: Rapor dosyaya yazılıyor...")
    ReportGenerator.generate(final_report)

    print("\n✅ Analiz tamamlandı!")
    print(f"   - Ham veri: raw_data.json")
    print(f"   - Ara bulgular: findings_intermediate.json")
    print(f"   - Nihai rapor: AI_Report.txt")
    print(f"   - Log: ai_analyzer.log")
    print()

    # Özet bilgi
    critical_count = sum(1 for f in all_findings if isinstance(f, dict) and f.get('severity') == 'critical')
    medium_count = sum(1 for f in all_findings if isinstance(f, dict) and f.get('severity') == 'medium')
    print(f"📊 Ön Bulgu Özeti: {len(all_findings)} bulgu tespit edildi.")
    print(f"   Kritik: {critical_count}, Orta: {medium_count}, Diğer: {len(all_findings) - critical_count - medium_count}")
    print(f"   Detaylar için AI_Report.txt dosyasını inceleyin.")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Program kullanıcı tarafından sonlandırıldı.")
        sys.exit(0)
    except Exception as e:
        logger.exception("Beklenmeyen hata:")
        print(f"\n❌ Beklenmeyen bir hata oluştu: {e}")
        print("Detaylar için ai_analyzer.log dosyasına bakın.")
        sys.exit(1)