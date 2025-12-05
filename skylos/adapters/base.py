class BaseAdapter:
    def __init__(self, model, api_key):
        self.model = model
        self.api_key = api_key

    def complete(self, _, user_prompt):
        raise NotImplementedError("Subclasses must implement this method")
