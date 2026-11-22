"""Build the incremental UML/code-review UI locally or in GitHub Actions."""
import sys
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY))
sys.path.insert(1, str(Path(__file__).resolve().parent))

from uml.runner import main

if __name__ == "__main__":
    raise SystemExit(main())
