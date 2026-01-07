from abc import ABC, abstractmethod


class BaseAdapter(ABC):
    def __init__(self, model, api_key):
        self.model = model
        self.api_key = api_key

    @abstractmethod
    def complete(self, system_prompt, user_prompt):
        pass
