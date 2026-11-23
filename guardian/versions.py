"""Small, dependency-free version comparison + range matching.

Covers npm semver ranges as used in advisories (">=1.0.0 <1.2.3 || =2.0.0"),
OSV ECOSYSTEM/SEMVER event ranges, and Maven/PyPI-ish dotted versions.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

_SEMVER = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[.-]?([0-9A-Za-z.-]+))?(?:\+.*)?$")


def _key_part(p: str):
    return (0, int(p), "") if p.isdigit() else (1, 0, p)


def vkey(v: str) -> Tuple:
    """Sort key. Release > prerelease of the same core version."""
    v = (v or "").strip()
    m = _SEMVER.match(v)
    if m:
        core = tuple(int(x or 0) for x in m.group(1, 2, 3))
        pre = m.group(4)
        # maven-style qualifiers that mean "release"
        if pre and pre.lower() in ("final", "release", "ga"):
            pre = None
        if pre is None:
            return core + ((1,),)
        return core + ((0,) + tuple(_key_part(p) for p in re.split(r"[.-]", pre)),)
    parts = re.split(r"[.\-_]", v)
    return tuple(_key_part(p) for p in parts if p)


def cmp(a: str, b: str) -> int:
    ka, kb = vkey(a), vkey(b)
    try:
        return (ka > kb) - (ka < kb)
    except TypeError:
        return (str(ka) > str(kb)) - (str(ka) < str(kb))


def is_prerelease(v: str) -> bool:
    k = vkey(v)
    return len(k) == 4 and isinstance(k[3], tuple) and k[3][:1] == (0,)


_COMP = re.compile(r"(<=|>=|<|>|=)?\s*v?([0-9A-Za-z.\-+*x]+)")


def satisfies(version: str, rng: str) -> bool:
    """npm-style range: comparator sets joined by '||'. Supports <,<=,>,>=,=, *, x, ^, ~ and hyphen ranges."""
    rng = (rng or "").strip()
    if rng in ("", "*", "x"):
        return True
    for alt in rng.split("||"):
        alt = alt.strip()
        if not alt:
            continue
        if " - " in alt:
            lo, hi = [s.strip() for s in alt.split(" - ", 1)]
            if cmp(version, lo) >= 0 and cmp(version, hi) <= 0:
                return True
            continue
        ok = True
        for tok in alt.replace(", ", " ").split():
            if not _match_token(version, tok):
                ok = False
                break
        if ok:
            return True
    return False


def _match_token(version: str, tok: str) -> bool:
    if tok in ("*", "x"):
        return True
    if tok[0] in "^~":
        base = tok[1:]
        parts = (base.split(".") + ["0", "0"])[:3]
        maj, mnr = int(parts[0]), int(parts[1] if parts[1].isdigit() else 0)
        if tok[0] == "^":
            upper = f"{maj + 1}.0.0" if maj > 0 else (f"0.{mnr + 1}.0" if mnr > 0 else f"0.0.{int(parts[2]) + 1}")
        else:
            upper = f"{maj}.{mnr + 1}.0"
        return cmp(version, base) >= 0 and cmp(version, upper) < 0
    m = _COMP.fullmatch(tok)
    if not m:
        return False
    op, target = m.group(1) or "=", m.group(2)
    if "*" in target or "x" in target.split("."):
        prefix = target.split(".")
        prefix = [p for p in prefix if p not in ("*", "x")]
        return version.split(".")[: len(prefix)] == prefix
    c = cmp(version, target)
    return {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "=": c == 0}[op]


def in_osv_range(version: str, events: List[dict]) -> bool:
    """OSV ECOSYSTEM/SEMVER range events: introduced / fixed / last_affected / limit."""
    affected = False
    for ev in sorted(events, key=lambda e: vkey(next(iter(e.values()))) if next(iter(e.values())) != "0" else (-1,)):
        if "introduced" in ev:
            intro = ev["introduced"]
            if intro == "0" or cmp(version, intro) >= 0:
                affected = True
        elif "fixed" in ev:
            if cmp(version, ev["fixed"]) >= 0:
                affected = False
        elif "last_affected" in ev:
            if cmp(version, ev["last_affected"]) > 0:
                affected = False
        elif "limit" in ev:
            if cmp(version, ev["limit"]) >= 0:
                affected = False
    return affected


def lowest_safe(current: str, candidates: List[str], vulnerable: callable) -> Optional[str]:
    """Smallest non-prerelease version >= current that the predicate says is not vulnerable."""
    for v in sorted((c for c in candidates if not is_prerelease(c)), key=vkey):
        if cmp(v, current) > 0 and not vulnerable(v):
            return v
    return None
