from pathlib import Path

from transformers import AutoTokenizer


def tokenizer_for(checkpoint_dir: Path):
    return AutoTokenizer.from_pretrained(str(checkpoint_dir))
