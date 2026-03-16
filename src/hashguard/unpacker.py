"""Automatic unpacking detection and support for HashGuard v2.

Detects common packers and provides unpacking capabilities:
- UPX detection and unpacking
- MPRESS, Themida, VMProtect detection
- Generic entropy-based packing detection
- Shellcode detection with API-hash heuristics and section-aware analysis
- Unicorn Engine emulation for generic unpacking (experimental)
"""

import math
import os
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from hashguard.logger import get_logger

logger = get_logger(__name__)

try:
    import pefile

    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64
    from unicorn.x86_const import (
        UC_X86_REG_ESP,
        UC_X86_REG_RSP,
        UC_X86_REG_EIP,
        UC_X86_REG_RIP,
    )

    HAS_UNICORN = True
except ImportError:
    HAS_UNICORN = False


@dataclass
class UnpackResult:
    was_packed: bool = False
    packer: str = ""
    unpacked: bool = False
    unpacked_path: str = ""
    original_size: int = 0
    unpacked_size: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "was_packed": self.was_packed,
            "packer": self.packer,
            "unpacked": self.unpacked,
            "unpacked_path": self.unpacked_path,
            "original_size": self.original_size,
            "unpacked_size": self.unpacked_size,
            "size_ratio": round(self.unpacked_size / max(self.original_size, 1), 2),
            "error": self.error,
        }


@dataclass
class ShellcodeInfo:
    detected: bool = False
    indicators: List[str] = field(default_factory=list)
    offset: int = -1
    size: int = 0
    confidence: str = "low"  # low, medium, high

    def to_dict(self) -> dict:
        return {
            "detected": self.detected,
            "indicators": self.indicators,
            "offset": self.offset,
            "size": self.size,
            "confidence": self.confidence,
        }


# ── Packer detection patterns ────────────────────────────────────────────────

PACKER_SIGNATURES = {
    "UPX": {
        "magic": [b"UPX0", b"UPX1", b"UPX!"],
        "section_names": ["UPX0", "UPX1", "UPX2"],
    },
    "MPRESS": {
        "magic": [b".MPRESS1", b".MPRESS2"],
        "section_names": [".MPRESS1", ".MPRESS2"],
    },
    "Themida": {
        "section_names": [".themida", ".Themida"],
        "strings": [b"Themida", b"Oreans"],
    },
    "VMProtect": {
        "section_names": [".vmp0", ".vmp1", ".VMP"],
        "strings": [b"VMProtect"],
    },
    "ASPack": {
        "section_names": [".aspack", ".adata"],
    },
    "PECompact": {
        "section_names": ["PEC2", "PECompact2"],
    },
    "Enigma": {
        "section_names": [".enigma1", ".enigma2"],
    },
    "NSPack": {
        "section_names": [".nsp0", ".nsp1", ".nsp2"],
    },
}


def detect_packer(file_path: str) -> tuple:
    """Detect if a file is packed and identify the packer."""
    try:
        content = Path(file_path).read_bytes()[: 1024 * 1024]  # First 1MB
    except OSError:
        return False, ""

    content_lower = content.lower()

    for packer_name, sigs in PACKER_SIGNATURES.items():
        # Check magic bytes
        for magic in sigs.get("magic", []):
            if magic in content:
                return True, packer_name

        # Check section names
        for sec_name in sigs.get("section_names", []):
            if sec_name.encode() in content:
                return True, packer_name

        # Check strings
        for s in sigs.get("strings", []):
            if s.lower() in content_lower:
                return True, packer_name

    return False, ""


def unpack_upx(file_path: str, output_dir: str = None) -> UnpackResult:
    """Attempt to unpack a UPX-packed file."""
    result = UnpackResult()
    result.original_size = os.path.getsize(file_path)

    is_packed, packer = detect_packer(file_path)
    result.was_packed = is_packed
    result.packer = packer

    if not is_packed:
        return result

    if packer != "UPX":
        result.error = f"Automatic unpacking only supported for UPX (detected: {packer})"
        return result

    # Find UPX binary
    upx_path = shutil.which("upx")
    if not upx_path:
        for p in [r"C:\upx\upx.exe", r"C:\Tools\upx.exe", os.path.expanduser("~/upx/upx.exe")]:
            if os.path.isfile(p):
                upx_path = p
                break

    if not upx_path:
        result.error = "UPX binary not found. Install UPX and add to PATH."
        return result

    # Create temp copy for unpacking
    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="hashguard_unpack_")

    unpacked_path = os.path.join(output_dir, f"unpacked_{os.path.basename(file_path)}")
    shutil.copy2(file_path, unpacked_path)

    try:
        proc = subprocess.run(
            [upx_path, "-d", unpacked_path],
            capture_output=True,
            timeout=30,
        )
        if proc.returncode == 0:
            result.unpacked = True
            result.unpacked_path = unpacked_path
            result.unpacked_size = os.path.getsize(unpacked_path)
        else:
            result.error = proc.stderr.decode("utf-8", errors="ignore")[:200]
    except FileNotFoundError:
        result.error = "UPX binary not found"
    except subprocess.TimeoutExpired:
        result.error = "Unpacking timed out"
    except Exception:
        result.error = "Unpacking failed"

    return result


# ── Shellcode Detection ──────────────────────────────────────────────────────

# High-confidence shellcode indicators (unlikely in benign code)
_SHELLCODE_STRONG = [
    (b"\x64\xa1\x30\x00\x00\x00", "PEB access via fs:[0x30] (shellcode TEB walk)"),
    (b"\x64\x8b\x1d\x30\x00\x00\x00", "PEB access variant (mov ebx, fs:[0x30])"),
    (b"\xe8\x00\x00\x00\x00", "call $+5 (position-independent shellcode)"),
    (b"\x64\x8b\x0d\x30\x00\x00\x00", "PEB access variant"),
]

# API hash resolution patterns — shellcode resolves imports by hash, not name
# These are common hash algorithms used in shellcode (CRC32, ROR13)
_API_HASH_PATTERNS = [
    # ROR13 hash resolution loop (used by Metasploit, Cobalt Strike)
    (b"\xc1\xcf\x0d", "ROR13 hash loop (Metasploit-style API resolution)"),
    # CRC32 loop
    (b"\x33\xd2\xf7\x74", "CRC32 API hash resolution"),
]

# Known API hashes (ROR13 of common DLL+function names)
_KNOWN_API_HASHES_ROR13 = {
    0x726774C: "kernel32.dll!LoadLibraryA",
    0x7C0DFCAA: "kernel32.dll!GetProcAddress",
    0xE8AFE98: "kernel32.dll!VirtualAlloc",
    0x56A2B5F0: "kernel32.dll!ExitProcess",
    0x0E553A458: "kernel32.dll!VirtualProtect",
    0x876F8B31: "ws2_32.dll!WSAStartup",
    0x6737DBC2: "ws2_32.dll!connect",
}

# Weak indicators — common in normal PE code, need corroboration
_SHELLCODE_WEAK = [
    (b"\x90" * 32, "NOP sled (32+ bytes)"),  # Require longer sled (16 too common)
    (b"\xcc" * 16, "INT3 breakpoint sled (16+ bytes)"),
    (b"\xeb\xfe", "Infinite loop (jmp short -2)"),
]


def _section_entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte buffer."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c > 0)


def _find_api_hashes(content: bytes) -> List[str]:
    """Scan for known API hash constants embedded in the binary."""
    found = []
    for hash_val, api_name in _KNOWN_API_HASHES_ROR13.items():
        # Look for the hash as a 4-byte little-endian constant
        needle = hash_val.to_bytes(4, "little")
        if needle in content:
            found.append(f"API hash for {api_name} at 0x{content.find(needle):X}")
    return found


def _get_non_code_regions(file_path: str) -> List[Tuple[int, int]]:
    """Return (offset, size) of PE sections NOT marked as executable.

    Shellcode hiding in data/resource sections is more suspicious than
    code in .text.
    """
    regions = []
    if not HAS_PEFILE:
        return regions
    try:
        pe = pefile.PE(file_path, fast_load=True)
        for sec in pe.sections:
            chars = sec.Characteristics
            is_exec = bool(chars & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
            if not is_exec:
                offset = sec.PointerToRawData
                size = sec.SizeOfRawData
                if offset and size:
                    regions.append((offset, size))
        pe.close()
    except Exception:
        pass
    return regions


def detect_shellcode(file_path: str) -> ShellcodeInfo:
    """Detect potential shellcode in a file with reduced false positives."""
    info = ShellcodeInfo()

    try:
        content = Path(file_path).read_bytes()
    except OSError:
        return info

    if len(content) < 32:
        return info

    strong_hits = 0
    weak_hits = 0

    # ── Strong indicators ────────────────────────────────────────────────────
    for pattern, description in _SHELLCODE_STRONG:
        idx = content.find(pattern)
        if idx >= 0:
            info.indicators.append(f"{description} at offset 0x{idx:X}")
            if info.offset < 0:
                info.offset = idx
            strong_hits += 1

    # ── API hash resolution patterns ─────────────────────────────────────────
    for pattern, description in _API_HASH_PATTERNS:
        if pattern in content:
            info.indicators.append(description)
            strong_hits += 1

    # ── Known API hash constants ─────────────────────────────────────────────
    api_hashes = _find_api_hashes(content)
    if len(api_hashes) >= 2:  # Need ≥2 different API hashes
        info.indicators.extend(api_hashes[:5])
        strong_hits += 1

    # ── Weak indicators (only count if in non-code sections) ─────────────────
    non_code = _get_non_code_regions(file_path)
    for pattern, description in _SHELLCODE_WEAK:
        idx = content.find(pattern)
        if idx >= 0:
            in_data_section = any(off <= idx < off + sz for off, sz in non_code)
            if in_data_section:
                info.indicators.append(f"{description} at offset 0x{idx:X} (data section)")
                weak_hits += 1
                if info.offset < 0:
                    info.offset = idx

    # ── High-entropy executable data in non-code sections ────────────────────
    for off, sz in non_code:
        chunk = content[off : off + sz]
        if len(chunk) > 256:
            ent = _section_entropy(chunk)
            if ent > 7.2:
                info.indicators.append(
                    f"High entropy ({ent:.2f}) in non-code section at 0x{off:X} ({sz} bytes)"
                )
                weak_hits += 1

    # ── Confidence scoring ───────────────────────────────────────────────────
    if strong_hits >= 2:
        info.detected = True
        info.confidence = "high"
    elif strong_hits == 1 and weak_hits >= 1:
        info.detected = True
        info.confidence = "medium"
    elif strong_hits == 1:
        info.detected = True
        info.confidence = "low"
    elif weak_hits >= 3:
        info.detected = True
        info.confidence = "low"

    return info


# ── Unicorn Engine Emulation Unpacking ────────────────────────────────────────

_EMU_MAX_INSTRUCTIONS = 500_000  # Safety limit
_EMU_STACK_SIZE = 0x10000  # 64 KB stack
_EMU_STACK_ADDR = 0x00100000  # Stack base


@dataclass
class EmulationUnpackResult:
    """Result from emulation-based unpacking attempt."""

    attempted: bool = False
    success: bool = False
    oep_found: bool = False
    oep_address: int = 0
    dumped_path: str = ""
    dumped_size: int = 0
    instructions_executed: int = 0
    written_regions: List[dict] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "attempted": self.attempted,
            "success": self.success,
            "oep_found": self.oep_found,
            "oep_address": hex(self.oep_address) if self.oep_address else "",
            "dumped_path": self.dumped_path,
            "dumped_size": self.dumped_size,
            "instructions_executed": self.instructions_executed,
            "written_regions": self.written_regions,
            "error": self.error,
        }


def emulate_unpack(file_path: str, output_dir: str = None) -> EmulationUnpackResult:
    """Attempt to unpack a PE by emulating its entry point with Unicorn Engine.

    Strategy:
    1. Load PE sections into emulated memory
    2. Execute from the entry point
    3. Track memory writes (the unpacking stub writes to the code section)
    4. Detect when execution jumps to a previously-written region (OEP)
    5. Dump the unpacked memory

    This is experimental and works best with simple packers (UPX, MPRESS,
    custom XOR stubs). Complex packers (Themida, VMProtect) use anti-emulation.
    """
    result = EmulationUnpackResult()

    if not HAS_UNICORN:
        result.error = "unicorn engine not installed (pip install unicorn)"
        return result

    if not HAS_PEFILE:
        result.error = "pefile not installed"
        return result

    result.attempted = True

    try:
        pe = pefile.PE(file_path, fast_load=False)
    except Exception as e:
        result.error = f"Failed to parse PE: {e}"
        return result

    is_64 = pe.FILE_HEADER.Machine == 0x8664
    mode = UC_MODE_64 if is_64 else UC_MODE_32
    image_base = pe.OPTIONAL_HEADER.ImageBase
    entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    entry_va = image_base + entry_rva

    try:
        uc = Uc(UC_ARCH_X86, mode)
    except Exception as e:
        result.error = f"Failed to init Unicorn: {e}"
        pe.close()
        return result

    # Map PE image: align to 4 KB pages
    image_size = pe.OPTIONAL_HEADER.SizeOfImage
    aligned_size = ((image_size + 0xFFF) & ~0xFFF) or 0x10000
    try:
        uc.mem_map(image_base, aligned_size)
        # Write PE headers
        uc.mem_write(image_base, pe.header[: pe.OPTIONAL_HEADER.SizeOfHeaders])
        # Write each section
        for sec in pe.sections:
            rva = sec.VirtualAddress
            data = sec.get_data()
            if data and rva < aligned_size:
                write_size = min(len(data), aligned_size - rva)
                uc.mem_write(image_base + rva, data[:write_size])
    except Exception as e:
        result.error = f"Failed to map PE: {e}"
        pe.close()
        return result

    # Setup stack
    try:
        uc.mem_map(_EMU_STACK_ADDR, _EMU_STACK_SIZE)
        sp = _EMU_STACK_ADDR + _EMU_STACK_SIZE - 0x1000
        if is_64:
            uc.reg_write(UC_X86_REG_RSP, sp)
        else:
            uc.reg_write(UC_X86_REG_ESP, sp)
    except Exception as e:
        result.error = f"Failed to setup stack: {e}"
        pe.close()
        return result

    # Track which code sections are "original" (written by loader)
    original_code_regions = set()
    for sec in pe.sections:
        if sec.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            start = image_base + sec.VirtualAddress
            end = start + sec.Misc_VirtualSize
            original_code_regions.add((start, end))

    # Track memory writes during emulation
    written_addresses = set()
    insn_count = [0]
    oep_candidate = [0]

    def _hook_mem_write(uc_obj, access, address, size, value, user_data):
        written_addresses.add(address)

    def _hook_code(uc_obj, address, size, user_data):
        insn_count[0] += 1
        # Check if we're executing from a region that was just written
        if address in written_addresses:
            # Potential OEP: execution jumped to freshly-written code
            oep_candidate[0] = address
            uc_obj.emu_stop()
            return
        if insn_count[0] >= _EMU_MAX_INSTRUCTIONS:
            uc_obj.emu_stop()

    try:
        from unicorn import UC_HOOK_MEM_WRITE, UC_HOOK_CODE

        uc.hook_add(UC_HOOK_MEM_WRITE, _hook_mem_write)
        uc.hook_add(UC_HOOK_CODE, _hook_code)
    except Exception as e:
        result.error = f"Failed to add hooks: {e}"
        pe.close()
        return result

    # Run emulation
    try:
        uc.emu_start(entry_va, image_base + aligned_size, timeout=10_000_000)  # 10s timeout
    except Exception:
        pass  # Emulation may stop due to unmapped memory, which is expected

    result.instructions_executed = insn_count[0]

    if oep_candidate[0]:
        result.oep_found = True
        result.oep_address = oep_candidate[0]

    # Record written regions summary
    if written_addresses:
        min_addr = min(written_addresses)
        max_addr = max(written_addresses)
        result.written_regions.append(
            {
                "start": hex(min_addr),
                "end": hex(max_addr),
                "unique_addresses": len(written_addresses),
            }
        )

    # Dump unpacked memory if we found something useful
    if written_addresses and (result.oep_found or len(written_addresses) > 100):
        if output_dir is None:
            output_dir = tempfile.mkdtemp(prefix="hashguard_emu_")

        dump_path = os.path.join(output_dir, f"emu_unpacked_{os.path.basename(file_path)}")
        try:
            # Read full image from emulator memory
            unpacked_data = uc.mem_read(image_base, aligned_size)
            # Patch entry point to OEP if found
            if result.oep_found:
                new_ep = result.oep_address - image_base
                # Patch AddressOfEntryPoint in the PE header
                ep_offset = pe.OPTIONAL_HEADER.get_file_offset() + 16  # AddressOfEntryPoint offset
                if ep_offset + 4 <= len(unpacked_data):
                    patched = bytearray(unpacked_data)
                    struct.pack_into("<I", patched, ep_offset, new_ep)
                    unpacked_data = bytes(patched)

            with open(dump_path, "wb") as f:
                f.write(unpacked_data)
            result.dumped_path = dump_path
            result.dumped_size = len(unpacked_data)
            result.success = True
        except Exception as e:
            result.error = f"Dump failed: {e}"
    else:
        result.error = "No significant memory writes detected during emulation"

    pe.close()
    return result


def auto_unpack(file_path: str, output_dir: str = None) -> UnpackResult:
    """Smart unpacking: tries UPX first, then falls back to emulation.

    Returns a standard UnpackResult. If emulation was used, the result
    includes emulation details in the error field (for informational purposes).
    """
    is_packed, packer = detect_packer(file_path)
    if not is_packed:
        return UnpackResult(was_packed=False)

    # Try native UPX unpacking first
    if packer == "UPX":
        result = unpack_upx(file_path, output_dir)
        if result.unpacked:
            return result

    # Fall back to emulation
    if HAS_UNICORN:
        emu_result = emulate_unpack(file_path, output_dir)
        result = UnpackResult(
            was_packed=True,
            packer=packer,
            unpacked=emu_result.success,
            unpacked_path=emu_result.dumped_path,
            original_size=os.path.getsize(file_path),
            unpacked_size=emu_result.dumped_size,
            error=(
                emu_result.error
                if not emu_result.success
                else (
                    f"Emulation unpacked (OEP: {hex(emu_result.oep_address)})"
                    if emu_result.oep_found
                    else "Emulation dump (no OEP)"
                )
            ),
        )
        return result

    return UnpackResult(
        was_packed=True,
        packer=packer,
        error=f"No unpacker available for {packer}. Install 'unicorn' for emulation-based unpacking.",
    )
