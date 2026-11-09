"""The trusted, source-only workflow dispatched after Cloud credit consent."""

import re

from skylos.cicd.agent_review import _cloud_origin
from skylos.cicd.workflow import PINNED_ACTIONS_SETUP_PYTHON


def generate_agent_review_workflow(
    *, skylos_version: str, cloud_url="https://skylos.dev"
) -> str:
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?", skylos_version):
        raise ValueError("Agent review requires an exact published Skylos version")
    origin = _cloud_origin(cloud_url)
    return f"""# Install on the default branch after publishing this Skylos release.
# PR source is downloaded as data by Cloud; it is never checked out or executed.
name: Skylos Agent Review

on:
  workflow_dispatch:
    inputs:
      review_id:
        description: Cloud-approved review ID
        type: string
        required: true

permissions:
  contents: read
  id-token: write

concurrency:
  group: skylos-agent-review-${{{{ inputs.review_id }}}}
  cancel-in-progress: false

jobs:
  review:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - name: Set up Python
        uses: {PINNED_ACTIONS_SETUP_PYTHON}
        with:
          python-version: '3.12'
      - name: Install trusted Skylos release
        run: python -m pip install --disable-pip-version-check 'skylos=={skylos_version}'
      - name: Run approved source review
        env:
          SKYLOS_REVIEW_ID: ${{{{ inputs.review_id }}}}
          SKYLOS_CLOUD_URL: {origin}
        run: skylos cicd agent-review --review-id "$SKYLOS_REVIEW_ID" --cloud-url "$SKYLOS_CLOUD_URL"
"""
