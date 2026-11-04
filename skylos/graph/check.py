"""Run ``skylos done`` for the viewer's Check this change button, one run at a time."""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
import threading
import time
from collections import deque
from collections.abc import Callable
from pathlib import Path

ENTRY = "import sys; from skylos.cli import main; sys.argv[0] = 'skylos'; sys.exit(main())"
LOG_LINES = 60
TIMEOUT_SECONDS = 1800
logger = logging.getLogger(__name__)
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

RESULT_TEXT = {
    0: ("passed", "Passed: nothing blocks this change."),
    1: ("blocked", "Blocked: click a red box below to see what to fix, or Copy fix brief for your coding agent."),
}


CHECK_CLIENT = "check-button"


def done_command(base: str) -> list[str]:
    return [sys.executable, "-c", ENTRY, "done", "--base", base, "--agent", CHECK_CLIENT]


class CheckRunner:
    def __init__(self, root: Path, base: str, after: Callable[[], None] | None = None):
        self.root = Path(root)
        self.base = base
        self.after = after
        self.lock = threading.Lock()
        self.process: subprocess.Popen | None = None
        self.stopping = threading.Event()
        self.record = {"state": "idle", "base": base, "log": []}

    def status(self) -> dict:
        with self.lock:
            snapshot = dict(self.record)
            snapshot["log"] = list(self.record["log"])
        snapshot["command"] = f"skylos done --base {self.base}"
        return snapshot

    def start(self) -> bool:
        with self.lock:
            if self.record["state"] == "running":
                return False
            self.record = {
                "state": "running",
                "base": self.base,
                "started_at": time.time(),
                "log": [],
                "message": "Running your tests and checks…",
            }
        threading.Thread(target=self._run, daemon=True).start()
        return True

    def stop(self) -> None:
        self.stopping.set()
        process = self.process
        if process is not None and process.poll() is None:
            process.terminate()

    def _finish(self, state: str, message: str, code: int | None) -> None:
        with self.lock:
            self.record.update(state=state, message=message, exit_code=code, finished_at=time.time())

    def _run(self) -> None:
        env = dict(os.environ, NO_COLOR="1", TERM="dumb", COLUMNS="110", PYTHONUNBUFFERED="1")
        tail: deque[str] = deque(maxlen=LOG_LINES)
        try:
            self.process = subprocess.Popen(
                done_command(self.base),
                cwd=self.root,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
            )
        except OSError as exc:
            self._finish("error", f"Could not start skylos done: {exc}", None)
            return
        timer = threading.Timer(TIMEOUT_SECONDS, self.stop)
        timer.daemon = True
        timer.start()
        try:
            for line in self.process.stdout:
                text = _ANSI.sub("", line.rstrip("\n"))
                tail.append(text)
                with self.lock:
                    self.record["log"] = list(tail)
            code = self.process.wait()
        finally:
            timer.cancel()
        if self.stopping.is_set():
            self._finish("error", "Stopped before it finished.", code)
            return
        if self.after is not None:
            try:
                self.after()
            except Exception:
                logger.debug("graph rebuild after check failed", exc_info=True)
        state, message = RESULT_TEXT.get(code, ("error", f"skylos done could not finish (exit {code}); see the output below."))
        self._finish(state, message, code)
