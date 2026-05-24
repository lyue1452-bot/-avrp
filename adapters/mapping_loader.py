"""YAML 自定义字段映射加载与解析。"""
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from adapters.base import BaseAdapter
from adapters.generic_csv import GenericCsvAdapter
from adapters.generic_json import GenericJsonAdapter, NAME_KEYS, SEV_KEYS, HOST_KEYS
from adapters.generic_xml import GenericXmlAdapter
from adapters.generic_markdown import GenericMarkdownAdapter
from adapters.utils import (
    load_json_file, load_json_or_jsonl, normalize_severity,
    parse_host_port, first_str, extract_cve,
)
from config import MAPPINGS_DIR
from models import VulnerabilityRecord


class YamlMappingAdapter(BaseAdapter):
    """按 mappings/*.yml 配置解析任意格式报告。"""

    def __init__(self, config: dict, path: Path):
        self.config = config
        self.path = path
        self.tool_name = config.get("tool_name", "custom")

    @classmethod
    def from_file(cls, mapping_path: Path, report_path: Path) -> "YamlMappingAdapter":
        with mapping_path.open(encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
        return cls(config, report_path)

    @classmethod
    def can_parse(cls, path: Path, sample: object) -> bool:
        return False

    def parse(self, path: Path) -> List[VulnerabilityRecord]:
        fmt = self._resolve_format(path)
        if fmt == "csv":
            cols = (self.config.get("csv") or {}).get("columns", {})
            return GenericCsvAdapter(column_map=cols, tool_name=self.tool_name).parse(path)
        if fmt == "xml":
            xml_cfg = self.config.get("xml") or {}
            return GenericXmlAdapter(
                record_xpath=xml_cfg.get("record_xpath", ""),
                field_tags=xml_cfg.get("fields", {}),
                tool_name=self.tool_name,
            ).parse(path)
        if fmt in ("md", "markdown"):
            md_cfg = self.config.get("md") or self.config.get("markdown") or {}
            return GenericMarkdownAdapter(md_config=md_cfg, tool_name=self.tool_name).parse(path)
        return self._parse_json(path)

    def _resolve_format(self, path: Path) -> str:
        fmt = (self.config.get("format") or "auto").lower()
        if fmt != "auto":
            return fmt
        suffix = path.suffix.lower()
        if suffix == ".csv":
            return "csv"
        if suffix in (".xml", ".nessus"):
            return "xml"
        if suffix in (".md", ".markdown"):
            return "md"
        return "json"

    def _parse_json(self, path: Path) -> List[VulnerabilityRecord]:
        json_cfg = self.config.get("json") or {}
        record_paths = json_cfg.get("record_path") or json_cfg.get("record_paths") or []
        field_map = json_cfg.get("fields") or {}

        try:
            data = load_json_or_jsonl(path)
        except Exception:
            data = load_json_file(path)

        items = self._extract_items(data, record_paths)
        if not items and isinstance(data, list):
            items = data

        if field_map:
            out = []
            for item in items:
                rec = self._map_json_item(item, field_map)
                if rec:
                    out.append(rec)
            return out

        adapter = GenericJsonAdapter()
        adapter.tool_name = self.tool_name
        return adapter.parse(path)

    def _extract_items(self, data: Any, record_paths: List) -> List[dict]:
        if not record_paths:
            return self._flatten_json(data)
        items = []
        for path_spec in record_paths:
            if isinstance(path_spec, str):
                path_spec = [path_spec]
            node = data
            for key in path_spec:
                if isinstance(node, dict) and key in node:
                    node = node[key]
                else:
                    node = None
                    break
            if isinstance(node, list):
                items.extend(node)
        return [i for i in items if isinstance(i, dict)]

    def _flatten_json(self, data: Any) -> List[dict]:
        found = []
        def walk(node):
            if isinstance(node, dict):
                if self._looks_like_vuln(node):
                    found.append(node)
                for v in node.values():
                    walk(v)
            elif isinstance(node, list):
                for item in node:
                    walk(item)
        walk(data)
        return found

    def _looks_like_vuln(self, d: dict) -> bool:
        has_name = any(k in d for k in (NAME_KEYS + ["name", "title"]))
        has_ctx = any(k in d for k in (SEV_KEYS + HOST_KEYS + ["url", "host", "ip"]))
        return has_name and has_ctx

    def _map_json_item(self, item: dict, field_map: dict) -> Optional[VulnerabilityRecord]:
        def pick(field):
            keys = field_map.get(field, [])
            if isinstance(keys, str):
                keys = [keys]
            return first_str(item, keys, "")

        name = pick("vuln_name")
        if not name:
            return None
        url = pick("url")
        host = pick("asset_ip")
        if url:
            asset_ip, port = parse_host_port(url)
        elif host:
            asset_ip, port = parse_host_port(host)
        else:
            return None

        port_s = pick("port")
        if port_s:
            try:
                port = int(str(port_s).split("/")[0])
            except ValueError:
                pass

        desc = pick("description")
        return VulnerabilityRecord(
            vuln_name=name,
            severity=normalize_severity(pick("severity") or "未知"),
            asset_ip=asset_ip.split()[0],
            port=port or 80,
            url=url or f"http://{asset_ip}:{port or 80}",
            description=desc[:2000],
            solution=pick("solution")[:2000],
            source_tool=self.tool_name,
            external_id=pick("external_id"),
            cve=pick("cve") or extract_cve(name + desc),
            cwe=pick("cwe"),
            plugin_id=pick("plugin_id"),
            owasp=pick("owasp"),
        )


def find_mapping_for_report(report_path: Path) -> Optional[Path]:
    """按文件名 / match 规则自动查找 mappings/*.yml。"""
    if not MAPPINGS_DIR.exists():
        return None

    report_name = report_path.stem.lower()
    text_head = ""
    try:
        text_head = report_path.read_text(encoding="utf-8", errors="replace")[:2000].lower()
    except Exception:
        pass

    best: Optional[Path] = None
    for yml in sorted(MAPPINGS_DIR.glob("*.yml")) + sorted(MAPPINGS_DIR.glob("*.yaml")):
        try:
            with yml.open(encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
        except Exception:
            continue

        match = cfg.get("match") or {}
        fn_patterns = match.get("filename_contains") or match.get("filename") or []
        content_patterns = match.get("content_contains") or match.get("content") or []

        if yml.stem.lower() == report_name:
            return yml

        for pat in fn_patterns:
            if pat.lower() in report_name:
                return yml

        for pat in content_patterns:
            if pat.lower() in text_head:
                best = yml

    return best


def load_mapping_adapter(report_path: Path, mapping_path: Optional[Path] = None) -> Optional[YamlMappingAdapter]:
    path = mapping_path or find_mapping_for_report(report_path)
    if not path or not path.exists():
        return None
    return YamlMappingAdapter.from_file(path, report_path)
