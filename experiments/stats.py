"""Means and 95 % confidence intervals over random seeds (Person 4)."""

from __future__ import annotations

import math
from typing import Iterable

# two-sided 95 % Student t, by degrees of freedom (used when scipy is not installed)
_T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306,
        9: 2.262, 10: 2.228, 15: 2.131, 20: 2.086, 30: 2.042}


def t95(df: int) -> float:
    try:
        from scipy import stats
        return float(stats.t.ppf(0.975, df))
    except ImportError:
        if df in _T95:
            return _T95[df]
        keys = sorted(_T95)
        return _T95[next((k for k in keys if k >= df), keys[-1])] if df < 30 else 1.96


def mean_ci(values: Iterable[float | None]) -> tuple[float | None, float | None, int]:
    """(mean, half-width of the 95 % CI, n). None values are skipped; one value has CI 0."""
    v = [float(x) for x in values if x is not None and not (isinstance(x, float) and math.isnan(x))]
    n = len(v)
    if n == 0:
        return None, None, 0
    m = sum(v) / n
    if n == 1:
        return m, 0.0, 1
    sd = math.sqrt(sum((x - m) ** 2 for x in v) / (n - 1))
    return m, t95(n - 1) * sd / math.sqrt(n), n
