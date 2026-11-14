from pathlib import Path

from transformers import AutoTokenizer


def tokenizer_for(checkpoint_dir: Path):
    return AutoTokenizer.from_pretrained(str(checkpoint_dir))


def tokenizer_offline(checkpoint_dir: Path):
    return AutoTokenizer.from_pretrained(str(checkpoint_dir), local_files_only=True)


def tokenizer_absolute():
    return AutoTokenizer.from_pretrained("/srv/models/tokenizer")
