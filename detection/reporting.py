"""Reporting rule: report a pseudonym after K flagged messages out of its last W.

The RSU logic (Person 3 / the stand-in protocol) keeps one window per pseudonym.
This class does the same for evaluation, so the K and W tuned here are the ones
the protocol should use (REPORT_K, REPORT_W).
"""

from __future__ import annotations

from collections import deque


class ReportingRule:
    def __init__(self, k: int = 3, w: int = 10) -> None:
        if not 1 <= k <= w:
            raise ValueError("need 1 <= K <= W")
        self.k, self.w = k, w
        self.windows: dict[str, deque] = {}
        self.reported: set[str] = set()

    def update(self, pid: str, flagged: bool, foreign: bool = False) -> bool:
        """Feed one message. True exactly once per pseudonym: when K of the last W are flagged.

        ``foreign`` messages (copies sent by someone else, features["foreign"]) are
        ignored: they say nothing about the owner of the pseudonym."""
        if foreign:
            return False
        win = self.windows.setdefault(pid, deque(maxlen=self.w))
        win.append(bool(flagged))
        if pid not in self.reported and sum(win) >= self.k:
            self.reported.add(pid)
            return True
        return False
