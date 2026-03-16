"""Memory layout and injection analysis for HashGuard.

Analyzes PE files for indicators of memory-based attack techniques:
- Process injection patterns (VirtualAlloc → WriteProcessMemory → CreateRemoteThread)
- RWX section detection (Read-Write-Execute = code injection surface)
- Section permission anomalies (writable code, executable data)
- Hollow process / PE unmapping indicators
- Memory-mapped I/O abuse patterns
- Suspicious memory API call chains
- Entry-point section anomalies (EP outside first section, EP in writable section)
- Import address table (IAT) anomalies suggesting runtime resolution / API hashing
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from hashguard.logger import get_logger

logger = get_logger(__name__)

try:
    import pefile

    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


# ── Injection technique API signatures ──────────────────────────────────────

# Each technique maps to a set of API imports that *together* indicate the
# technique.  Partial matches raise confidence proportionally.

INJECTION_TECHNIQUES: Dict[str, Dict] = {
    "classic_injection": {
        "description": "Classic remote process injection (VirtualAllocEx → WriteProcessMemory → CreateRemoteThread)",
        "required_apis": {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
        "optional_apis": {"OpenProcess", "NtWriteVirtualMemory"},
        "mitre": "T1055.001",
        "severity": "critical",
    },
    "apc_injection": {
        "description": "APC queue injection for code execution in target thread",
        "required_apis": {"QueueUserAPC", "OpenThread"},
        "optional_apis": {"VirtualAllocEx", "WriteProcessMemory", "SuspendThread", "ResumeThread"},
        "mitre": "T1055.004",
        "severity": "critical",
    },
    "process_hollowing": {
        "description": "Process hollowing — unmaps legitimate image and replaces with malicious PE",
        "required_apis": {"CreateProcessA", "NtUnmapViewOfSection"},
        "optional_apis": {
            "CreateProcessW", "WriteProcessMemory", "SetThreadContext",
            "ResumeThread", "VirtualAllocEx", "ZwUnmapViewOfSection",
        },
        "mitre": "T1055.012",
        "severity": "critical",
    },
    "atom_bombing": {
        "description": "AtomBombing — abuses global atom table for write-what-where",
        "required_apis": {"GlobalAddAtomA", "NtQueueApcThread"},
        "optional_apis": {"GlobalAddAtomW", "GlobalGetAtomNameA", "GlobalGetAtomNameW"},
        "mitre": "T1055",
        "severity": "high",
    },
    "dll_injection": {
        "description": "DLL injection via LoadLibrary in remote process",
        "required_apis": {"CreateRemoteThread", "LoadLibraryA"},
        "optional_apis": {
            "LoadLibraryW", "VirtualAllocEx", "WriteProcessMemory",
            "OpenProcess", "GetProcAddress",
        },
        "mitre": "T1055.001",
        "severity": "high",
    },
    "map_view_injection": {
        "description": "Section-based injection via mapped views",
        "required_apis": {"NtCreateSection", "NtMapViewOfSection"},
        "optional_apis": {
            "ZwCreateSection", "ZwMapViewOfSection", "NtUnmapViewOfSection",
            "CreateFileMappingA", "MapViewOfFile",
        },
        "mitre": "T1055.012",
        "severity": "high",
    },
    "thread_hijack": {
        "description": "Thread context hijacking for code execution",
        "required_apis": {"SuspendThread", "SetThreadContext"},
        "optional_apis": {
            "GetThreadContext", "ResumeThread", "OpenThread",
            "VirtualAllocEx", "WriteProcessMemory",
        },
        "mitre": "T1055.003",
        "severity": "critical",
    },
    "early_bird_injection": {
        "description": "Early Bird — APC injection before process initializes",
        "required_apis": {"QueueUserAPC", "ResumeThread"},
        "optional_apis": {
            "CreateProcessA", "CreateProcessW", "VirtualAllocEx",
            "WriteProcessMemory",
        },
        "mitre": "T1055.004",
        "severity": "critical",
    },
    "heap_spray": {
        "description": "Heap spray — fills heap with NOP sleds or shellcode",
        "required_apis": {"HeapCreate", "HeapAlloc"},
        "optional_apis": {"RtlAllocateHeap", "VirtualAlloc", "HeapFree"},
        "mitre": "T1203",
        "severity": "medium",
    },
    "memory_guard_change": {
        "description": "Changing memory page protection (e.g. RW→RX for shellcode execution)",
        "required_apis": {"VirtualProtect"},
        "optional_apis": {
            "VirtualProtectEx", "NtProtectVirtualMemory",
            "VirtualAlloc", "VirtualAllocEx",
        },
        "mitre": "T1055",
        "severity": "medium",
    },
}

# Individual suspicious memory APIs (any single import is a signal)
SUSPICIOUS_MEMORY_APIS = {
    "NtWriteVirtualMemory", "NtReadVirtualMemory",
    "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
    "NtCreateThreadEx", "RtlCreateUserThread",
    "NtQueueApcThread", "ZwWriteVirtualMemory",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    "NtMapViewOfSection", "ZwMapViewOfSection",
    "NtCreateSection", "ZwCreateSection",
    "WriteProcessMemory", "ReadProcessMemory",
    "VirtualAllocEx", "VirtualProtectEx",
    "CreateRemoteThread", "CreateRemoteThreadEx",
    "SetThreadContext", "GetThreadContext",
    "QueueUserAPC",
}

# APIs that indicate runtime import resolution (API hashing / dynamic linking)
DYNAMIC_RESOLVE_APIS = {
    "GetProcAddress", "LdrGetProcedureAddress",
    "LdrGetDllHandle", "LdrLoadDll",
}


# ── Section flag constants ──────────────────────────────────────────────────

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040


# ── Data classes ────────────────────────────────────────────────────────────

@dataclass
class InjectionTechnique:
    name: str
    description: str
    matched_apis: List[str] = field(default_factory=list)
    missing_apis: List[str] = field(default_factory=list)
    confidence: float = 0.0
    mitre: str = ""
    severity: str = "medium"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "matched_apis": self.matched_apis,
            "missing_apis": self.missing_apis,
            "confidence": round(self.confidence, 2),
            "mitre": self.mitre,
            "severity": self.severity,
        }


@dataclass
class SectionPermission:
    name: str
    virtual_address: int = 0
    virtual_size: int = 0
    raw_size: int = 0
    entropy: float = 0.0
    is_rwx: bool = False
    is_writable_code: bool = False
    is_executable_data: bool = False
    flags: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "virtual_address": hex(self.virtual_address),
            "virtual_size": self.virtual_size,
            "raw_size": self.raw_size,
            "entropy": round(self.entropy, 3),
            "is_rwx": self.is_rwx,
            "is_writable_code": self.is_writable_code,
            "is_executable_data": self.is_executable_data,
            "flags": self.flags,
        }


@dataclass
class EntryPointAnomaly:
    ep_section: str = ""
    ep_rva: int = 0
    is_outside_code: bool = False
    is_writable: bool = False
    is_last_section: bool = False
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "ep_section": self.ep_section,
            "ep_rva": hex(self.ep_rva),
            "is_outside_code": self.is_outside_code,
            "is_writable": self.is_writable,
            "is_last_section": self.is_last_section,
            "description": self.description,
        }


@dataclass
class MemoryAnalysisResult:
    """Full memory analysis report."""
    injection_techniques: List[InjectionTechnique] = field(default_factory=list)
    suspicious_sections: List[SectionPermission] = field(default_factory=list)
    entry_point: Optional[EntryPointAnomaly] = None
    suspicious_api_count: int = 0
    suspicious_apis_found: List[str] = field(default_factory=list)
    has_dynamic_resolve: bool = False
    dynamic_resolve_apis: List[str] = field(default_factory=list)
    rwx_section_count: int = 0
    total_techniques_detected: int = 0
    max_severity: str = "none"
    risk_score: int = 0
    summary: str = ""

    def to_dict(self) -> dict:
        d: dict = {
            "injection_techniques": [t.to_dict() for t in self.injection_techniques],
            "suspicious_sections": [s.to_dict() for s in self.suspicious_sections],
            "suspicious_api_count": self.suspicious_api_count,
            "suspicious_apis_found": self.suspicious_apis_found,
            "has_dynamic_resolve": self.has_dynamic_resolve,
            "dynamic_resolve_apis": self.dynamic_resolve_apis,
            "rwx_section_count": self.rwx_section_count,
            "total_techniques_detected": self.total_techniques_detected,
            "max_severity": self.max_severity,
            "risk_score": self.risk_score,
            "summary": self.summary,
        }
        if self.entry_point:
            d["entry_point"] = self.entry_point.to_dict()
        return d


# ── Core analysis functions ─────────────────────────────────────────────────

def _get_imported_apis(pe: "pefile.PE") -> set:
    """Extract all imported API names from a PE file."""
    apis: set = set()
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    try:
                        apis.add(imp.name.decode("ascii", errors="ignore"))
                    except Exception:
                        pass
    return apis


def _section_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte block."""
    if not data:
        return 0.0
    import math

    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / length
            entropy -= p * math.log2(p)
    return entropy


def _flags_string(characteristics: int) -> str:
    """Convert section characteristics to R/W/X string."""
    parts = []
    if characteristics & IMAGE_SCN_MEM_READ:
        parts.append("R")
    if characteristics & IMAGE_SCN_MEM_WRITE:
        parts.append("W")
    if characteristics & IMAGE_SCN_MEM_EXECUTE:
        parts.append("X")
    return "".join(parts)


def _detect_injection_techniques(apis: set) -> List[InjectionTechnique]:
    """Match imported APIs against known injection technique signatures."""
    techniques: List[InjectionTechnique] = []

    # Case-insensitive matching
    api_lower = {a.lower() for a in apis}

    for tech_name, tech_def in INJECTION_TECHNIQUES.items():
        required = tech_def["required_apis"]
        optional = tech_def.get("optional_apis", set())
        all_relevant = required | optional

        matched = {a for a in all_relevant if a.lower() in api_lower}
        required_matched = {a for a in required if a.lower() in api_lower}

        if not required_matched:
            continue

        # Confidence = (required matched / required total) * 0.7 +
        # (optional matched / optional total) * 0.3
        req_ratio = len(required_matched) / len(required) if required else 0
        opt_matched = matched - required_matched
        opt_ratio = len(opt_matched) / len(optional) if optional else 0
        confidence = req_ratio * 0.7 + opt_ratio * 0.3

        # Only report if at least 50% of required APIs matched
        if req_ratio < 0.5:
            continue

        missing = sorted(required - required_matched)

        techniques.append(InjectionTechnique(
            name=tech_name,
            description=tech_def["description"],
            matched_apis=sorted(matched),
            missing_apis=missing,
            confidence=confidence,
            mitre=tech_def.get("mitre", ""),
            severity=tech_def.get("severity", "medium"),
        ))

    # Sort by confidence descending
    techniques.sort(key=lambda t: t.confidence, reverse=True)
    return techniques


def _analyze_sections(pe: "pefile.PE") -> List[SectionPermission]:
    """Analyze PE sections for permission anomalies."""
    suspicious: List[SectionPermission] = []

    for section in pe.sections:
        try:
            name = section.Name.decode("ascii", errors="ignore").strip("\x00")
        except Exception:
            name = "<unknown>"

        chars = section.Characteristics
        is_exec = bool(chars & IMAGE_SCN_MEM_EXECUTE)
        is_write = bool(chars & IMAGE_SCN_MEM_WRITE)
        is_read = bool(chars & IMAGE_SCN_MEM_READ)
        is_code = bool(chars & IMAGE_SCN_CNT_CODE)
        is_data = bool(chars & IMAGE_SCN_CNT_INITIALIZED_DATA)

        rwx = is_exec and is_write and is_read
        writable_code = is_code and is_write
        exec_data = is_data and is_exec and not is_code

        if rwx or writable_code or exec_data:
            data = section.get_data()
            entropy = _section_entropy(data)
            suspicious.append(SectionPermission(
                name=name,
                virtual_address=section.VirtualAddress,
                virtual_size=section.Misc_VirtualSize,
                raw_size=section.SizeOfRawData,
                entropy=entropy,
                is_rwx=rwx,
                is_writable_code=writable_code,
                is_executable_data=exec_data,
                flags=_flags_string(chars),
            ))

    return suspicious


def _analyze_entry_point(pe: "pefile.PE") -> Optional[EntryPointAnomaly]:
    """Check if entry point is in an unusual section."""
    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    if ep_rva == 0:
        return None

    sections = list(pe.sections)
    if not sections:
        return None

    ep_section_idx = -1
    ep_section_name = "<outside>"
    for i, section in enumerate(sections):
        start = section.VirtualAddress
        end = start + section.Misc_VirtualSize
        if start <= ep_rva < end:
            ep_section_idx = i
            try:
                ep_section_name = section.Name.decode("ascii", errors="ignore").strip("\x00")
            except Exception:
                ep_section_name = f"section_{i}"
            break

    anomaly = EntryPointAnomaly(
        ep_section=ep_section_name,
        ep_rva=ep_rva,
    )

    descriptions = []

    if ep_section_idx == -1:
        anomaly.is_outside_code = True
        descriptions.append("Entry point is outside all sections")
    else:
        section = sections[ep_section_idx]
        chars = section.Characteristics

        if chars & IMAGE_SCN_MEM_WRITE:
            anomaly.is_writable = True
            descriptions.append("Entry point is in a writable section")

        if ep_section_idx == len(sections) - 1 and len(sections) > 1:
            anomaly.is_last_section = True
            descriptions.append("Entry point is in the last section (common in packed binaries)")

    # Only return if there's something anomalous
    if not descriptions:
        return None

    anomaly.description = "; ".join(descriptions)
    return anomaly


def analyze_memory(file_path: str, pe_info: Optional[dict] = None) -> MemoryAnalysisResult:
    """Perform memory layout and injection analysis on a PE file.

    Args:
        file_path: Path to the PE file.
        pe_info: Optional pre-computed PE analysis dict (from pe_analyzer).

    Returns:
        MemoryAnalysisResult with all findings.
    """
    result = MemoryAnalysisResult()

    if not HAS_PEFILE:
        result.summary = "pefile not available"
        return result

    try:
        pe = pefile.PE(file_path, fast_load=False)
    except Exception as e:
        logger.debug(f"Cannot parse PE for memory analysis: {e}")
        result.summary = "Not a valid PE file"
        return result

    try:
        # 1. Extract imported APIs
        apis = _get_imported_apis(pe)

        # 2. Detect injection techniques
        result.injection_techniques = _detect_injection_techniques(apis)
        result.total_techniques_detected = len(result.injection_techniques)

        # 3. Find suspicious individual memory APIs
        found_suspicious = sorted(apis & SUSPICIOUS_MEMORY_APIS)
        result.suspicious_apis_found = found_suspicious
        result.suspicious_api_count = len(found_suspicious)

        # 4. Check for dynamic resolve APIs (API hashing / runtime resolution)
        found_dynamic = sorted(apis & DYNAMIC_RESOLVE_APIS)
        result.has_dynamic_resolve = bool(found_dynamic)
        result.dynamic_resolve_apis = found_dynamic

        # 5. Analyze section permissions
        result.suspicious_sections = _analyze_sections(pe)
        result.rwx_section_count = sum(1 for s in result.suspicious_sections if s.is_rwx)

        # 6. Entry point anomalies
        result.entry_point = _analyze_entry_point(pe)

        # 7. Compute risk score (0-100) and max severity
        result.risk_score, result.max_severity = _compute_risk(result)

        # 8. Build summary
        result.summary = _build_summary(result)

    except Exception as e:
        logger.debug(f"Memory analysis error: {e}")
        result.summary = "Analysis error"
    finally:
        pe.close()

    return result


# ── Risk scoring ────────────────────────────────────────────────────────────

_SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _compute_risk(result: MemoryAnalysisResult) -> tuple:
    """Compute a 0-100 risk score and max severity from findings."""
    score = 0
    max_sev = "none"

    # Injection techniques
    for tech in result.injection_techniques:
        if tech.confidence >= 0.7:
            score += {"critical": 30, "high": 20, "medium": 10}.get(tech.severity, 5)
        elif tech.confidence >= 0.5:
            score += {"critical": 15, "high": 10, "medium": 5}.get(tech.severity, 3)
        if _SEVERITY_ORDER.get(tech.severity, 0) > _SEVERITY_ORDER.get(max_sev, 0):
            max_sev = tech.severity

    # RWX sections
    score += result.rwx_section_count * 15
    if result.rwx_section_count > 0 and _SEVERITY_ORDER.get(max_sev, 0) < _SEVERITY_ORDER["high"]:
        max_sev = "high"

    # Writable code / executable data sections (non-RWX)
    non_rwx_suspicious = sum(
        1 for s in result.suspicious_sections
        if (s.is_writable_code or s.is_executable_data) and not s.is_rwx
    )
    score += non_rwx_suspicious * 8
    if non_rwx_suspicious > 0 and _SEVERITY_ORDER.get(max_sev, 0) < _SEVERITY_ORDER["medium"]:
        max_sev = "medium"

    # Suspicious APIs (counted individually, diminishing returns)
    api_score = min(result.suspicious_api_count * 3, 20)
    score += api_score
    if result.suspicious_api_count >= 3 and _SEVERITY_ORDER.get(max_sev, 0) < _SEVERITY_ORDER["medium"]:
        max_sev = "medium"

    # Dynamic resolve APIs
    if result.has_dynamic_resolve:
        score += 5

    # Entry point anomalies
    if result.entry_point:
        if result.entry_point.is_outside_code:
            score += 15
            if _SEVERITY_ORDER.get(max_sev, 0) < _SEVERITY_ORDER["high"]:
                max_sev = "high"
        if result.entry_point.is_writable:
            score += 10
        if result.entry_point.is_last_section:
            score += 5

    return min(score, 100), max_sev


def _build_summary(result: MemoryAnalysisResult) -> str:
    """Build a human-readable summary of findings."""
    parts = []

    if result.total_techniques_detected:
        names = [t.name.replace("_", " ") for t in result.injection_techniques[:3]]
        parts.append(f"{result.total_techniques_detected} injection technique(s): {', '.join(names)}")

    if result.rwx_section_count:
        parts.append(f"{result.rwx_section_count} RWX section(s)")

    non_rwx = [s for s in result.suspicious_sections if not s.is_rwx]
    if non_rwx:
        anomalies = []
        if any(s.is_writable_code for s in non_rwx):
            anomalies.append("writable code")
        if any(s.is_executable_data for s in non_rwx):
            anomalies.append("executable data")
        if anomalies:
            parts.append(f"Section anomalies: {', '.join(anomalies)}")

    if result.entry_point:
        parts.append(f"EP anomaly: {result.entry_point.description}")

    if result.has_dynamic_resolve:
        parts.append("Dynamic API resolution detected")

    if result.suspicious_api_count > 0 and not result.total_techniques_detected:
        parts.append(f"{result.suspicious_api_count} suspicious memory API(s)")

    if not parts:
        return "No memory-related threats detected"

    return "; ".join(parts)
