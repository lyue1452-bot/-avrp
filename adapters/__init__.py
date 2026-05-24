"""自动识别并解析多工具漏洞报告。"""
from pathlib import Path
from typing import List, Optional, Tuple, Type

from adapters.base import BaseAdapter
from adapters.rayscan import RayScanAdapter
from adapters.nuclei import NucleiAdapter
from adapters.sarif import SarifAdapter
from adapters.nessus import NessusCsvAdapter, NessusXmlAdapter, OpenVasJsonAdapter
from adapters.burp import BurpXmlAdapter
from adapters.generic_json import GenericJsonAdapter
from adapters.generic_csv import GenericCsvAdapter
from adapters.generic_xml import GenericXmlAdapter
from adapters.generic_markdown import GenericMarkdownAdapter
from adapters.mapping_loader import load_mapping_adapter
from adapters.utils import load_json_file, load_json_or_jsonl
from models import VulnerabilityRecord

DEDICATED_JSON: List[Type[BaseAdapter]] = [
    RayScanAdapter,
    NucleiAdapter,
    SarifAdapter,
    OpenVasJsonAdapter,
]


def _peek(path: Path):
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return "csv"
    if suffix in (".json", ".jsonl"):
        try:
            return load_json_or_jsonl(path)
        except Exception:
            try:
                return load_json_file(path)
            except Exception:
                return None
    if suffix in (".xml", ".nessus"):
        return path.read_text(encoding="utf-8", errors="replace")[:800]
    if suffix in (".md", ".markdown"):
        return path.read_text(encoding="utf-8", errors="replace")[:800]
    return None


def _detect_dedicated(path: Path, sample: object) -> Optional[BaseAdapter]:
    suffix = path.suffix.lower()

    if suffix in (".json", ".jsonl") and isinstance(sample, (dict, list)):
        for cls in DEDICATED_JSON:
            if cls.can_parse(path, sample):
                return cls()

    if suffix == ".csv":
        adapter = NessusCsvAdapter()
        if adapter.parse(path):
            return adapter
        return None

    if suffix in (".xml", ".nessus") and isinstance(sample, str):
        if BurpXmlAdapter.can_parse(path, sample):
            return BurpXmlAdapter()
        if NessusXmlAdapter.can_parse(path, sample):
            adapter = NessusXmlAdapter()
            if adapter.parse(path):
                return adapter
    return None


def _fallback_adapter(path: Path) -> BaseAdapter:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return GenericCsvAdapter()
    if suffix in (".xml", ".nessus"):
        return GenericXmlAdapter()
    if suffix in (".md", ".markdown"):
        return GenericMarkdownAdapter()
    return GenericJsonAdapter()


def parse_report(
    path: Path,
    mapping_path: Optional[Path] = None,
) -> Tuple[List[VulnerabilityRecord], str]:
    path = Path(path)

    if mapping_path:
        mapped = load_mapping_adapter(path, Path(mapping_path))
        if mapped:
            records = mapped.parse(path)
            return records, mapped.tool_name

    sample = _peek(path)
    dedicated = _detect_dedicated(path, sample)
    if dedicated:
        records = dedicated.parse(path)
        if records:
            return records, dedicated.tool_name

    mapped = load_mapping_adapter(path)
    if mapped:
        records = mapped.parse(path)
        if records:
            return records, mapped.tool_name

    fallback = _fallback_adapter(path)
    records = fallback.parse(path)
    return records, fallback.tool_name
