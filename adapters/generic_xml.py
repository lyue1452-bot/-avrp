"""通用 XML：递归识别漏洞条目节点 + 可选 YAML XPath 配置。"""
import re
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Set

from adapters.base import BaseAdapter
from adapters.field_synonyms import score_header, FIELD_SYNONYMS
from adapters.utils import normalize_severity, parse_host_port, extract_cve
from models import VulnerabilityRecord


def _strip_ns(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


class GenericXmlAdapter(BaseAdapter):
    tool_name = "generic_xml"

    def __init__(
        self,
        record_xpath: str = "",
        field_tags: Optional[Dict[str, List[str]]] = None,
        tool_name: str = "",
    ):
        self.record_xpath = record_xpath
        self.field_tags = field_tags or {}
        if tool_name:
            self.tool_name = tool_name

    @classmethod
    def can_parse(cls, path: Path, sample: object) -> bool:
        return path.suffix.lower() in (".xml", ".nessus")

    def parse(self, path: Path) -> List[VulnerabilityRecord]:
        root = ET.parse(path).getroot()
        records: List[VulnerabilityRecord] = []
        seen: Set[str] = set()

        if self.record_xpath:
            nodes = root.findall(self.record_xpath)
            for node in nodes:
                rec = self._element_to_record(node)
                if rec:
                    fp = rec.compute_fingerprint()
                    if fp not in seen:
                        seen.add(fp)
                        records.append(rec)
            return records

        candidates = self._find_record_elements(root)
        for el in candidates:
            rec = self._element_to_record(el)
            if rec:
                fp = rec.compute_fingerprint()
                if fp not in seen:
                    seen.add(fp)
                    records.append(rec)
        return records

    def _find_record_elements(self, root: ET.Element) -> List[ET.Element]:
        """找出最像「漏洞记录」的重复元素组。"""
        tag_groups: Dict[str, List[ET.Element]] = {}
        for el in root.iter():
            tag = _strip_ns(el.tag).lower()
            if len(list(el)) == 0 and not el.attrib:
                continue
            tag_groups.setdefault(tag, []).append(el)

        scored: List[tuple] = []
        for tag, elements in tag_groups.items():
            if len(elements) < 1:
                continue
            sample = elements[0]
            score = self._score_element_as_record(sample)
            if score >= 1.5:
                scored.append((score * len(elements), elements))

        if not scored:
            for el in root.iter():
                sc = self._score_element_as_record(el)
                if sc >= 2.0:
                    scored.append((sc, [el]))

        scored.sort(key=lambda x: x[0], reverse=True)
        if not scored:
            return []

        best_elements = scored[0][1]
        if len(best_elements) >= 2:
            return best_elements

        all_good = []
        best_tag = _strip_ns(best_elements[0].tag).lower()
        for el in root.iter():
            if _strip_ns(el.tag).lower() == best_tag and self._score_element_as_record(el) >= 1.5:
                all_good.append(el)
        return all_good or best_elements

    def _score_element_as_record(self, el: ET.Element) -> float:
        score = 0.0
        keys = self._collect_keys(el)
        for field in ("vuln_name", "severity", "asset_ip", "url"):
            for k in keys:
                if score_header(k, field) >= 0.7:
                    score += 1.0
                    break
        return score

    def _collect_keys(self, el: ET.Element) -> List[str]:
        keys = list(el.attrib.keys())
        for child in el:
            keys.append(_strip_ns(child.tag))
        return keys

    def _element_to_record(self, el: ET.Element) -> Optional[VulnerabilityRecord]:
        data = self._extract_fields(el)
        name = data.get("vuln_name", "")
        if not name:
            return None

        url = data.get("url", "")
        host = data.get("asset_ip", "")
        if url:
            asset_ip, port = parse_host_port(url)
        elif host:
            asset_ip, port = parse_host_port(host)
        else:
            return None

        port_s = data.get("port", "")
        if port_s:
            try:
                port = int(re.sub(r"[^\d]", "", str(port_s)) or "0") or port
            except ValueError:
                pass

        desc = data.get("description", "")
        cve = data.get("cve", "") or extract_cve(name + desc)

        return VulnerabilityRecord(
            vuln_name=name,
            severity=normalize_severity(data.get("severity", "未知")),
            asset_ip=asset_ip.split()[0],
            port=port or 80,
            url=url or f"http://{asset_ip}:{port or 80}",
            description=desc[:2000],
            solution=data.get("solution", "")[:2000],
            source_tool=self.tool_name,
            plugin_id=data.get("plugin_id", ""),
            cve=cve,
            cwe=data.get("cwe", ""),
            owasp=data.get("owasp", ""),
        )

    def _extract_fields(self, el: ET.Element) -> Dict[str, str]:
        pool: Dict[str, str] = {}

        for attr, val in el.attrib.items():
            pool[_strip_ns(attr).lower()] = str(val)

        for child in el:
            tag = _strip_ns(child.tag).lower()
            text = (child.text or "").strip()
            if child.tail:
                pass
            if text:
                pool[tag] = text
            for sub in child:
                sub_tag = _strip_ns(sub.tag).lower()
                sub_text = (sub.text or "").strip()
                if sub_text:
                    pool[sub_tag] = sub_text

        if self.field_tags:
            return self._map_with_config(pool, el)
        return self._map_with_synonyms(pool, el)

    def _map_with_config(self, pool: Dict[str, str], el: ET.Element) -> Dict[str, str]:
        result = {}
        for field, specs in self.field_tags.items():
            for spec in specs:
                spec = spec.lstrip("@")
                if spec.startswith("@") or spec in el.attrib:
                    key = spec.lstrip("@")
                    if key in el.attrib:
                        result[field] = el.attrib[key]
                        break
                low = spec.lower()
                if low in pool:
                    result[field] = pool[low]
                    break
        return result

    def _map_with_synonyms(self, pool: Dict[str, str], el: ET.Element) -> Dict[str, str]:
        result = {}
        for field in FIELD_SYNONYMS:
            best_key = None
            best_score = 0.55
            for key in pool:
                sc = score_header(key, field)
                if sc > best_score:
                    best_score = sc
                    best_key = key
            if best_key:
                result[field] = pool[best_key]
        return result
