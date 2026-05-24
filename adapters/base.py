"""报告适配器基类。"""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from models import VulnerabilityRecord


class BaseAdapter(ABC):
    tool_name: str = "unknown"

    @abstractmethod
    def parse(self, path: Path) -> List[VulnerabilityRecord]:
        pass

    @classmethod
    def can_parse(cls, path: Path, sample: object) -> bool:
        return False
