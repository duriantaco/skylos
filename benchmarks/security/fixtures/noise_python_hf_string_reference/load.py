from transformers import AutoModel


def load_named(model_dir: str):
    return AutoModel.from_pretrained(model_dir)
