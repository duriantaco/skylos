from abc import ABC, abstractmethod


class BaseWorker(ABC):
    @abstractmethod
    def run(self):
        raise NotImplementedError
