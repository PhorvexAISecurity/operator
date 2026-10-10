"""Deterministic interval estimators for Math Lab metrics.

Every estimator returns None instead of a number when its input cannot support one; a
missing estimate is never reported as zero.
"""
import math
import random

Z95 = 1.959963984540054
DEFAULT_RESAMPLES = 2000
DEFAULT_SEED = 20261009


def wilson(numerator, denominator, z=Z95):
    """Wilson score interval for a binomial proportion."""
    if denominator is None or denominator <= 0 or numerator is None:
        return None
    if numerator < 0 or numerator > denominator:
        raise ValueError('numerator outside [0, denominator]')
    p = numerator / denominator
    denom = 1 + z * z / denominator
    centre = (p + z * z / (2 * denominator)) / denom
    half = z * math.sqrt(p * (1 - p) / denominator + z * z / (4 * denominator * denominator)) / denom
    low, high = centre - half, centre + half
    # Clamp to [0,1] and remove floating-point residue at the boundaries.
    low = 0.0 if low < 1e-12 else low
    high = 1.0 if high > 1 - 1e-12 else high
    return [low, high]


def _percentile(sorted_values, q):
    if not sorted_values:
        return None
    pos = (len(sorted_values) - 1) * q
    lo, hi = math.floor(pos), math.ceil(pos)
    if lo == hi:
        return sorted_values[lo]
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (pos - lo)


def bootstrap_mean(values, resamples=DEFAULT_RESAMPLES, seed=DEFAULT_SEED):
    """Percentile bootstrap of the mean over independent units (e.g. snapshots/ticks)."""
    values = [v for v in values if v is not None and math.isfinite(v)]
    if len(values) < 2:
        return None
    rng = random.Random(seed)
    n = len(values)
    means = sorted(sum(values[rng.randrange(n)] for _ in range(n)) / n for _ in range(resamples))
    return [_percentile(means, .025), _percentile(means, .975)]


def bootstrap_ratio(pairs, resamples=DEFAULT_RESAMPLES, seed=DEFAULT_SEED):
    """Cluster bootstrap of sum(num)/sum(den) where each pair is one cluster (one tick)."""
    pairs = [(a, b) for a, b in pairs if b is not None and b > 0 and a is not None]
    if len(pairs) < 2:
        return None
    rng = random.Random(seed)
    n = len(pairs)
    out = []
    for _ in range(resamples):
        num = den = 0
        for _ in range(n):
            a, b = pairs[rng.randrange(n)]
            num += a
            den += b
        out.append(num / den)
    out.sort()
    return [_percentile(out, .025), _percentile(out, .975)]


def paired_bootstrap_diff(diffs, resamples=DEFAULT_RESAMPLES, seed=DEFAULT_SEED):
    """Percentile bootstrap of the mean paired difference (arm - control) over matched units."""
    return bootstrap_mean(diffs, resamples, seed)


def mean(values):
    values = [v for v in values if v is not None and math.isfinite(v)]
    return sum(values) / len(values) if values else None


def quantile(values, q):
    values = sorted(v for v in values if v is not None and math.isfinite(v))
    return _percentile(values, q)


def holm(p_values):
    """Holm step-down adjustment; returns adjusted p-values in input order."""
    indexed = sorted(enumerate(p_values), key=lambda x: x[1])
    m = len(p_values)
    adjusted = [None] * m
    running = 0.0
    for rank, (i, p) in enumerate(indexed):
        running = max(running, min(1.0, (m - rank) * p))
        adjusted[i] = running
    return adjusted


def mcnemar_exact(b, c):
    """Exact two-sided McNemar p-value from discordant counts b and c."""
    n = b + c
    if n == 0:
        return None
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    return min(1.0, 2 * tail)
