from abc import ABC, abstractmethod


class SkylosRule(ABC):
    """Base class for all Skylos rules"""

    @property
    @abstractmethod
    def rule_id(self):
        pass

    @property
    @abstractmethod
    def name(self):
        pass

    @abstractmethod
    def visit_node(self, node, context):
        pass
