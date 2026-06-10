"""通用 Markdown 渗透/漏扫报告智能解析。"""
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from adapters.base import BaseAdapter
from adapters.field_synonyms import score_header, normalize_key
from adapters.utils import normalize_severity, parse_host_port, extract_cve
from models import VulnerabilityRecord

# 章节标题中的严重级别标记
SEVERITY_IN_TITLE = re.compile(
    r"\[?(critical|high|medium|low|info|高危|中危|低危|信息|高风险|中风险|低风险)\]?",
    re.I,
)

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
URL_RE = re.compile(r"https?://[^\s\)>\"']+", re.I)
PORT_RE = re.compile(r"(?:端口|port)\s*[:：]?\s*(\d{1,5})", re.I)
PORTS_MULTI_RE = re.compile(r"(\d{1,5})(?:/tcp|/udp)?(?:\s*,\s*|\s+)", re.I)

# 键值行：**级别**: 高危  / - Host: 1.2.3.4  / 描述：xxx
KV_LINE = re.compile(
    r"^[\s>*\-]*(?:\*\*)?(?P<key>[^\*:\n：]+?)(?:\*\*)?\s*[:：]\s*(?P<val>.+?)\s*$",
    re.M,
)

HEADER_SPLIT = re.compile(r"^(#{1,4})\s+(.+)$", re.M)

# 漏洞ID格式：V-001, V-002, 等等
VULN_ID_RE = re.compile(r"^### V-(\d+):\s*(.+?)(?:\s*\(([^)]+)\))?\s*$", re.M)

# 漏洞总览表中的行格式：V-001 | 漏洞名 | 端口 | CVSS | 严重程度
VULN_TABLE_ROW_RE = re.compile(r"V-\d+")

FIELD_KEY_MAP = {
    "vuln_name": ["漏洞", "漏洞名称", "名称", "name", "title", "finding", "issue", "威胁"],
    "severity": ["级别", "severity", "risk", "危险程度", "风险", "等级", "严重程度"],
    "asset_ip": ["主机", "host", "ip", "ip address", "目标", "target", "资产", "地址"],
    "port": ["端口", "port", "影响端口"],
    "url": ["url", "链接", "link", "地址", "location", "路径", "影响 url"],
    "description": ["描述", "description", "详情", "detail", "summary", "说明", "synopsis"],
    "solution": ["修复", "修复建议", "solution", "remediation", "建议", "recommendation", "缓解"],
    "cve": ["cve"],
    "plugin_id": ["plugin", "plugin id", "编号", "id", "漏洞id"],
    "cvss": ["cvss", "cvss评分", "cvss score"],
}


class GenericMarkdownAdapter(BaseAdapter):
    tool_name = "generic_md"

    def __init__(self, md_config: Optional[dict] = None, tool_name: str = ""):
        self.md_config = md_config or {}
        if tool_name:
            self.tool_name = tool_name

    @classmethod
    def can_parse(cls, path: Path, sample: object) -> bool:
        return path.suffix.lower() in (".md", ".markdown")

    def parse(self, path: Path) -> List[VulnerabilityRecord]:
        text = path.read_text(encoding="utf-8", errors="replace")
        records: List[VulnerabilityRecord] = []
        seen = set()
        default_target_ip = self._extract_default_target_ip(text)

        # 优先解析详细漏洞描述章节（### V-###: 格式）
        for rec in self._parse_vuln_detail_sections(text):
            if default_target_ip and (not rec.asset_ip or rec.asset_ip == "unknown"):
                rec.asset_ip = default_target_ip
                if not rec.url or rec.url.startswith("http://unknown"):
                    rec.url = f"http://{rec.asset_ip}:{rec.port or 80}"
            fp = rec.compute_fingerprint()
            if fp not in seen:
                seen.add(fp)
                records.append(rec)

        # 然后解析表格（特别是漏洞总览表）
        for rec in self._parse_tables(text):
            if default_target_ip and (not rec.asset_ip or rec.asset_ip == "unknown"):
                rec.asset_ip = default_target_ip
                if not rec.url or rec.url.startswith("http://unknown"):
                    rec.url = f"http://{rec.asset_ip}:{rec.port or 80}"
            fp = rec.compute_fingerprint()
            if fp not in seen:
                seen.add(fp)
                records.append(rec)

        # 解析通用章节
        for rec in self._parse_sections(text):
            if default_target_ip and (not rec.asset_ip or rec.asset_ip == "unknown"):
                rec.asset_ip = default_target_ip
                if not rec.url or rec.url.startswith("http://unknown"):
                    rec.url = f"http://{rec.asset_ip}:{rec.port or 80}"
            fp = rec.compute_fingerprint()
            if fp not in seen:
                seen.add(fp)
                records.append(rec)

        # 最后兜底：列表块
        if not records:
            for rec in self._parse_list_blocks(text):
                if default_target_ip and (not rec.asset_ip or rec.asset_ip == "unknown"):
                    rec.asset_ip = default_target_ip
                    if not rec.url or rec.url.startswith("http://unknown"):
                        rec.url = f"http://{rec.asset_ip}:{rec.port or 80}"
                fp = rec.compute_fingerprint()
                if fp not in seen:
                    seen.add(fp)
                    records.append(rec)

        return records

    def _extract_default_target_ip(self, text: str) -> str:
        """从报告元数据中提取默认目标IP。"""
        # 优先匹配目标IP字段
        for m in KV_LINE.finditer(text):
            key = m.group("key").strip()
            val = m.group("val").strip()
            if normalize_key(key) in {"目标ip", "目标", "ip", "targetip", "target", "目标地址"}:
                ip_match = IP_RE.search(val)
                if ip_match:
                    return ip_match.group(0)
        # 如果没有直观字段，则从前部文本寻找第一个 IP
        head_text = text[:1000]
        ip_m = IP_RE.search(head_text)
        return ip_m.group(0) if ip_m else ""

    def _normalize_vuln_id(self, vuln_id: str) -> str:
        if not vuln_id:
            return ""
        normalized = str(vuln_id).strip().upper()
        normalized = re.sub(r"^V-?", "", normalized)
        return normalized or "0"

    def _parse_vuln_detail_sections(self, text: str) -> List[VulnerabilityRecord]:

        """解析 ### V-###: 漏洞名称 (严重程度) 格式的详细漏洞描述章节。"""
        records = []
        lines = text.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            # 匹配 ### V-###: 漏洞名称 (严重程度) 格式
            m = re.match(r"^### V-(\d+):\s*(.+?)(?:\s*\(([^)]+)\))?\s*$", line, re.I)
            if m:
                vuln_id = self._normalize_vuln_id(m.group(1))
                vuln_name = m.group(2).strip()
                severity_hint = m.group(3).strip() if m.group(3) else ""
                
                # 收集该章节的内容
                i += 1
                body_lines = []
                while i < len(lines):
                    next_line = lines[i].strip()
                    # 遇到下一个章节或标题停止
                    if next_line.startswith("#"):
                        break
                    body_lines.append(lines[i])
                    i += 1
                
                body = "\n".join(body_lines)
                rec = self._section_to_record(vuln_name, body, vuln_id=vuln_id, severity_hint=severity_hint)
                if rec:
                    records.append(rec)
            else:
                i += 1
        
        return records

    def _parse_tables(self, text: str) -> List[VulnerabilityRecord]:
        records = []
        lines = text.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith("|") and i + 1 < len(lines) and re.match(r"^\|[\s\-:|]+\|$", lines[i + 1].strip()):
                headers = [c.strip() for c in line.strip("|").split("|")]
                col_map = self._map_headers(headers)
                
                # 检查表格是否包含漏洞相关字段
                if "vuln_name" not in col_map and "asset_ip" not in col_map and not any(
                    "ID" in h or "漏洞名" in h for h in headers
                ):
                    i += 1
                    continue
                
                i += 2
                while i < len(lines) and lines[i].strip().startswith("|"):
                    cells = [c.strip() for c in lines[i].strip("|").split("|")]
                    row = dict(zip(headers, cells))
                    
                    # 特殊处理漏洞总览表（包含V-ID的行）
                    is_vuln_table = any("V-" in cell for cell in cells)
                    
                    if is_vuln_table:
                        rec = self._parse_vuln_overview_row(row, col_map)
                    else:
                        rec = self._row_dict_to_record(row, col_map)
                    
                    if rec:
                        records.append(rec)
                    i += 1
                continue
            i += 1
        return records

    def _parse_vuln_overview_row(self, row: dict, col_map: dict) -> Optional[VulnerabilityRecord]:
        """解析漏洞总览表中的行（包含V-ID、漏洞名、端口、CVSS评分、严重程度等字段）。"""
        # 查找漏洞名字段
        vuln_name = None
        vuln_id = None
        
        for cell_val in row.values():
            if cell_val.startswith("V-"):
                vuln_id = cell_val
            elif cell_val and len(cell_val) > 3 and not cell_val.startswith("V-"):
                # 第二个非ID的列通常是漏洞名称
                if not vuln_name:
                    vuln_name = cell_val
                    break
        
        # 从col_map获取字段
        def get(field):
            h = col_map.get(field)
            return row.get(h, "").strip() if h else ""
        
        # 如果col_map未映射，直接使用行数据
        if not vuln_name:
            vuln_name = get("vuln_name")
        
        if vuln_name:
            vuln_name = re.sub(r'^(V-?\d+[:：]?\s*)', '', vuln_name, flags=re.I).strip()
        
        if not vuln_name:
            # 尝试从所有单元格获取第一个非ID、非数字的项
            for cell_val in row.values():
                if cell_val and not cell_val.startswith("V-") and not cell_val[0].isdigit() and len(cell_val) > 2:
                    if not re.match(r"^\d+\.\d+", cell_val):  # 不是CVSS评分
                        vuln_name = cell_val
                        break
        
        if not vuln_name or len(vuln_name) < 2:
            return None
        
        # 提取端口信息 - 可能包含多个端口 (3306/tcp, 445/tcp, 等)
        ports_str = get("port") or ""
        port_list = []
        if ports_str:
            # 提取所有数字端口
            for m in re.finditer(r'(\d{1,5})', ports_str):
                try:
                    p = int(m.group(1))
                    if 1 <= p <= 65535:
                        port_list.append(p)
                except ValueError:
                    pass
        
        port = port_list[0] if port_list else 80
        
        # 提取IP地址
        asset_ip = get("asset_ip") or ""
        if not asset_ip:
            # 从端口字段尝试提取IP (可能格式为 IP:端口)
            ports_str_maybe_ip = get("port") or ""
            if "/" in ports_str_maybe_ip:
                ip_match = IP_RE.search(ports_str_maybe_ip.split("/")[0])
                if ip_match:
                    asset_ip = ip_match.group(0)
        
        if not asset_ip:
            asset_ip = "unknown"
        else:
            asset_ip = asset_ip.split()[0]  # 只取第一个IP
        
        # 提取严重程度
        severity = get("severity") or ""
        if not severity:
            # 从其他字段寻找严重程度标记
            for cell_val in row.values():
                if any(s in cell_val for s in ["高", "中", "低", "critical", "high", "medium", "low"]):
                    severity = cell_val
                    break
        
        severity = normalize_severity(severity or "未知")
        
        # 提取CVSS评分和CVE
        cvss = get("cvss") or ""
        url = get("url") or f"http://{asset_ip}:{port or 80}"
        description = f"ID: {vuln_id}\n来源: 漏洞总览表"
        solution = get("solution") or ""
        cve = get("cve") or ""
        if not cve:
            cve = extract_cve(vuln_name)
        
        normalized_id = self._normalize_vuln_id(vuln_id) if vuln_id else ""
        return VulnerabilityRecord(
            vuln_name=vuln_name[:500],
            severity=severity,
            asset_ip=asset_ip,
            port=port or 80,
            url=url,
            description=description[:2000],
            solution=solution[:2000],
            source_tool=self.tool_name,
            cve=cve,
            plugin_id=normalized_id or "",
            external_id=normalized_id or "",
        )

    def _parse_sections(self, text: str) -> List[VulnerabilityRecord]:
        records = []
        min_level = int(self.md_config.get("section_level", 2))
        sections = self._split_sections(text, min_level=min_level)

        skip_titles = set(
            normalize_key(t) for t in (self.md_config.get("skip_titles") or [
                "summary", "overview", "目录", "概述", "摘要", "introduction", "changelog",
                "漏洞清单", "漏洞列表", "finding list", "vulnerability list", "清单", "列表",
            ])
        )

        for title, body in sections:
            if normalize_key(title) in skip_titles:
                continue
            if self._body_is_table_only(body):
                continue
            if not self._section_looks_like_vuln(title, body):
                continue
            rec = self._section_to_record(title, body)
            if rec:
                records.append(rec)
        return records

    def _parse_list_blocks(self, text: str) -> List[VulnerabilityRecord]:
        """兜底：按 --- 或空行分段。"""
        records = []
        blocks = re.split(r"\n---+\n|\n\n(?=\*\*|\- )", text)
        for block in blocks:
            block = block.strip()
            if len(block) < 20:
                continue
            title_m = re.search(r"^#{1,4}\s+(.+)$", block, re.M)
            title = title_m.group(1).strip() if title_m else ""
            if not title:
                name_m = re.search(r"(?:漏洞|finding|issue)\s*[:：]\s*(.+)", block, re.I)
                title = name_m.group(1).strip() if name_m else ""
            if title and self._section_looks_like_vuln(title, block):
                rec = self._section_to_record(title, block)
                if rec:
                    records.append(rec)
        return records

    def _split_sections(self, text: str, min_level: int = 2) -> List[Tuple[str, str]]:
        matches = list(HEADER_SPLIT.finditer(text))
        if not matches:
            return []

        sections = []
        for idx, m in enumerate(matches):
            level = len(m.group(1))
            if level < min_level:
                continue
            title = m.group(2).strip()
            start = m.end()
            end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
            body = text[start:end].strip()
            sections.append((title, body))
        return sections

    def _body_is_table_only(self, body: str) -> bool:
        lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
        if not lines:
            return False
        table_lines = sum(1 for ln in lines if ln.startswith("|"))
        return table_lines >= 2 and table_lines >= len(lines) * 0.6

    def _section_title_is_noise(self, title: str) -> bool:
        title_lower = title.lower()
        noise_keywords = [
            "扫描", "测试", "验证", "命令", "输出", "结果", "工具", "报告元", "概述", "安装",
            "风险", "评估", "改进建议", "目录", "未安装", "操作系统", "端口扫描", "状态变化",
            "初始扫描", "验证扫描", "whatweb", "nikto", "waf检测", "目录枚举", "实际连接测试",
            "详细漏洞描述", "已安装渗透测试工具", "未安装工具", "综合风险评估",
            "立即修复", "短期修复", "长期修复",
        ]
        if any(keyword in title_lower for keyword in noise_keywords):
            return True
        # 排除中文章节编号标题如“四、端口3306 — MySQL数据库”，除非显式包含漏洞或V-标识
        if re.match(r'^[一二三四五六七八九十]+、', title.strip()):
            if "漏洞" in title_lower or "v-" in title_lower or "暴露" in title_lower or "未设置" in title_lower:
                return False
            return True
        if re.match(r'^[0-9]+、', title.strip()):
            if "漏洞" in title_lower or "v-" in title_lower or "暴露" in title_lower or "未设置" in title_lower:
                return False
            return True
        # 排除纯风险评估小节标题
        if title_lower.startswith("风险") and "漏洞" not in title_lower and "v-" not in title_lower:
            return True
        # 避免重复解析 V- 开头的详尽漏洞段落
        if re.match(r'^v-\d+', title_lower):
            return True
        return False

    def _section_looks_like_vuln(self, title: str, body: str) -> bool:
        if self._section_title_is_noise(title):
            return False
        blob = (title + " " + body).lower()
        vuln_hints = [
            "漏洞", "vuln", "cve-", "severity", "high-risk", "medium-risk", "low-risk",
            "xss", "sql", "csrf", "injection", "header", "cookie", "ssl", "tls", "weak", "弱",
            "缺失", "未设置", "exposure", "misconfig", "finding", "issue", "威胁", "暴露",
        ]
        if SEVERITY_IN_TITLE.search(title):
            return True
        if any(h in blob for h in vuln_hints):
            return True
        return False

    def _section_to_record(self, title: str, body: str, vuln_id: str = "", severity_hint: str = "") -> Optional[VulnerabilityRecord]:
        fields = self._extract_kv_fields(body)
        name = self._clean_title(title) or fields.get("vuln_name", "")
        if not name or len(name) < 2:
            return None

        # 如果有明确的严重程度提示（从标题中），优先使用
        sev = severity_hint or fields.get("severity") or self._severity_from_title(title) or "未知"
        url = fields.get("url", "")
        host = fields.get("asset_ip", "")

        if url:
            asset_ip, port = parse_host_port(url)
        elif host:
            asset_ip, port = parse_host_port(host)
        else:
            asset_ip, port = self._guess_host_from_text(body)

        port_s = fields.get("port", "")
        if port_s:
            try:
                # 处理多个端口的情况，取第一个
                ports = re.findall(r'\d{1,5}', port_s)
                if ports:
                    port = int(ports[0])
            except (ValueError, IndexError):
                pass

        desc = fields.get("description", "")
        if not desc:
            desc = self._body_as_description(body)
        
        # 如果有vuln_id，添加到描述中
        if vuln_id:
            desc = f"漏洞ID: {vuln_id}\n" + desc

        sol = fields.get("solution", "")
        cve = fields.get("cve", "") or extract_cve(title + body)

        return VulnerabilityRecord(
            vuln_name=name[:500],
            severity=normalize_severity(sev),
            asset_ip=asset_ip.split()[0] if asset_ip != "unknown" else "unknown",
            port=port or 80,
            url=url or f"http://{asset_ip}:{port or 80}",
            description=desc[:2000],
            solution=sol[:2000],
            source_tool=self.tool_name,
            cve=cve,
            plugin_id=vuln_id or fields.get("plugin_id", ""),
            external_id=vuln_id or "",
        )

    def _extract_kv_fields(self, text: str) -> Dict[str, str]:
        result = {}
        custom = (self.md_config.get("fields") or {})
        for m in KV_LINE.finditer(text):
            key = m.group("key").strip()
            val = m.group("val").strip().strip("*").strip()
            if not val:
                continue
            if custom:
                for field, aliases in custom.items():
                    alias_list = aliases if isinstance(aliases, list) else [aliases]
                    if any(normalize_key(key) == normalize_key(a) for a in alias_list):
                        result[field] = val
                        break
            else:
                for field, aliases in FIELD_KEY_MAP.items():
                    if score_header(key, field) >= 0.7 or normalize_key(key) in [normalize_key(a) for a in aliases]:
                        result[field] = val
                        break
        return result

    def _map_headers(self, headers: List[str]) -> Dict[str, str]:
        col_map = {}
        custom = (self.md_config.get("table_columns") or self.md_config.get("fields") or {})
        for field in FIELD_KEY_MAP:
            if field in custom:
                specs = custom[field] if isinstance(custom[field], list) else [custom[field]]
                for h in headers:
                    if any(normalize_key(h) == normalize_key(s) for s in specs):
                        col_map[field] = h
                        break
            else:
                best_h, best_s = None, 0.55
                for h in headers:
                    lower_h = h.lower()
                    if field == "cve" and "cve" not in normalize_key(h):
                        continue
                    if field == "severity" and "cvss" in lower_h:
                        continue
                    sc = score_header(h, field)
                    if sc > best_s:
                        best_s, best_h = sc, h
                if best_h:
                    col_map[field] = best_h
        return col_map

    def _row_dict_to_record(self, row: dict, col_map: dict) -> Optional[VulnerabilityRecord]:
        def get(field):
            h = col_map.get(field)
            return row.get(h, "").strip() if h else ""

        name = get("vuln_name")
        if not name:
            return None
        url = get("url")
        host = get("asset_ip")
        if url:
            asset_ip, port = parse_host_port(url)
        elif host:
            asset_ip, port = parse_host_port(host)
        else:
            return None

        port_s = get("port")
        if port_s:
            try:
                # 处理多个端口的情况，取第一个
                ports = re.findall(r'\d{1,5}', port_s)
                if ports:
                    port = int(ports[0])
            except (ValueError, IndexError):
                pass

        desc = get("description")
        solution_s = get("solution")
        return VulnerabilityRecord(
            vuln_name=name,
            severity=normalize_severity(get("severity") or "未知"),
            asset_ip=asset_ip.split()[0] if asset_ip and asset_ip != "unknown" else asset_ip,
            port=port or 80,
            url=url or f"http://{asset_ip}:{port or 80}",
            description=desc[:2000] if desc else "",
            solution=solution_s[:2000] if solution_s else "",
            source_tool=self.tool_name,
            cve=get("cve") or extract_cve(name + (desc or "")),
            plugin_id=get("plugin_id"),
        )

    def _clean_title(self, title: str) -> str:
        t = re.sub(r"^\d+[\.\)、]\s*", "", title.strip())
        t = SEVERITY_IN_TITLE.sub("", t).strip()
        t = re.sub(r"^[\[\(【].*?[\]\)】]\s*", "", t).strip()
        return t.strip(":-— ")

    def _severity_from_title(self, title: str) -> str:
        m = SEVERITY_IN_TITLE.search(title)
        return m.group(1) if m else ""

    def _guess_host_from_text(self, text: str) -> Tuple[str, int]:
        """从文本中猜测主机IP和端口。"""
        url_m = URL_RE.search(text)
        if url_m:
            url = url_m.group(0).strip().strip('`"\' ).,;')
            return parse_host_port(url)
        ip_m = IP_RE.search(text)
        if ip_m:
            host = ip_m.group(0)
            # 查找端口 - 可能在 host:port 格式或单独的端口字段
            port_matches = re.findall(r'(\d{1,5})(?:/tcp|/udp)?', text)
            port = 80
            if port_matches:
                try:
                    for p_str in port_matches:
                        p = int(p_str)
                        if 1 <= p <= 65535 and p != int(host.split(".")[-1]):  # 排除可能是IP的数字
                            port = p
                            break
                except ValueError:
                    pass
            return host, port
        return "unknown", 80

    def _body_as_description(self, body: str) -> str:
        """从正文中提取有效的描述文本（去除格式标记）。"""
        lines = []
        max_lines = 10  # 限制描述行数
        for line in body.splitlines():
            if len(lines) >= max_lines:
                break
            s = line.strip()
            if not s or s.startswith("#") or s.startswith("|"):
                continue
            if KV_LINE.match(s):
                continue
            # 去除Markdown格式标记
            s = re.sub(r'\*\*(.+?)\*\*', r'\1', s)
            s = re.sub(r'`(.+?)`', r'\1', s)
            lines.append(s)
        return "\n".join(lines)[:2000]
