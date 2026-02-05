from abc import ABC, abstractmethod
from typing import Any, Optional
import ast


class SkylosRule(ABC):
    """Base class for all Skylos rules"""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def visit_node(
        self, node: ast.AST, context: dict[str, Any]
    ) -> Optional[list[dict[str, Any]]]:
        pass
