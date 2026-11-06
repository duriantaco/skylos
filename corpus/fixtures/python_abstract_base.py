from abc import ABC, abstractmethod


class BaseWorker(ABC):
    @abstractmethod
    def run(self):
        raise NotImplementedError


class FileWorker:
    def process(self):
        return None


FileWorker()
