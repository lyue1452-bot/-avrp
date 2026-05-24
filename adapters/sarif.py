"""SARIF 2.x（GitHub CodeQL、部分 SAST/扫描器导出）。"""
from pathlib import Path
from typing import List

from adapters.base import BaseAdapter
from adapters.utils import load_json_file, normalize_severity, parse_host_port, extract_cve
from models import VulnerabilityRecord


class SarifAdapter(BaseAdapter):
    tool_name = "sarif"

    @classmethod
    def can_parse(cls, path: Path, sample: object) -> bool:
        return (
            isinstance(sample, dict)
            and "runs" in sample
            and ("$schema" in sample or "version" in sample)
        )

    def parse(self, path: Path) -> List[VulnerabilityRecord]:
        data = load_json_file(path)
        records: List[VulnerabilityRecord] = []

        for run in data.get("runs", []):
            tool = run.get("tool", {}).get("driver", {}).get("name", "sarif")
            rules = {}
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                rules[rule.get("id", "")] = rule

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                rule = rules.get(rule_id, {})
                msg = result.get("message", {})
                title = msg.get("text") if isinstance(msg, dict) else str(msg or rule_id)
                if not title and rule:
                    title = rule.get("shortDescription", {}).get("text", rule_id)

                level = result.get("level") or rule.get("defaultConfiguration", {}).get("level", "warning")
                severity = normalize_severity(level)
                locations = result.get("locations", [])
                url = ""
                host, port = "unknown", 80
                if locations:
                    phys = locations[0].get("physicalLocation", {})
                    artifact = phys.get("artifactLocation", {})
                    url = artifact.get("uri", "")
                    if url.startswith("http"):
                        host, port = parse_host_port(url)

                desc_parts = []
                if rule.get("fullDescription", {}).get("text"):
                    desc_parts.append(rule["fullDescription"]["text"])
                for fix in result.get("fixes", []):
                    desc_parts.append(str(fix))

                help_uri = ""
                for rel in rule.get("relationships", []):
                    if rel.get("target", {}).get("id"):
                        help_uri = rel["target"]["id"]
                solution = help_uri or rule.get("helpUri", "")

                records.append(VulnerabilityRecord(
                    vuln_name=title or rule_id,
                    severity=severity,
                    asset_ip=host,
                    port=port,
                    url=url,
                    description="\n".join(desc_parts)[:2000],
                    solution=str(solution)[:1000],
                    source_tool=tool,
                    external_id=rule_id,
                    cve=extract_cve(title + rule_id),
                    plugin_id=rule_id,
                ))
        return records
