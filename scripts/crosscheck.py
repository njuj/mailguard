"""Compare mailguard's SPF verdicts with pyspf, the long-standing reference implementation.

    pip install pyspf dnspython
    python scripts/crosscheck.py domains.txt

For every domain with an SPF record, both evaluate a sender at 192.0.2.1 (TEST-NET-1, never authorized by
anyone), which makes a receiver walk the whole record. They must agree on whether the result is permerror,
and on the DNS lookup count when it isn't. Prints the agreement rate and every disagreement.
"""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import spf  # pyspf

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mailguard.resolver import Resolver  # noqa: E402
from mailguard.spf import evaluate_spf, find_spf  # noqa: E402

resolver = Resolver(timeout=15)


def one(domain: str):
    try:
        records = find_spf(resolver.query(domain, "TXT"))
    except Exception as e:  # noqa: BLE001
        return domain, None, f"dns: {e}"
    if not records:
        return domain, None, None
    mine = evaluate_spf(domain, records, resolver)
    q = spf.query(i="192.0.2.1", s=f"postmaster@{domain}", h=domain, timeout=20)
    result, _, explanation = q.check()
    if result == "temperror":
        return domain, None, "pyspf temperror"
    return domain, (mine, result, explanation, q.lookups), None


def main(path: str) -> int:
    domains = [d.strip() for d in Path(path).read_text().split() if d.strip()]
    with ThreadPoolExecutor(16) as pool:
        rows = list(pool.map(one, domains))
    compared = [(d, r) for d, r, _ in rows if r]
    perm_agree = count_agree = counted = 0
    for d, (mine, result, expl, lookups) in compared:
        theirs_perm = result == "permerror"
        if bool(mine.permerror) == theirs_perm:
            perm_agree += 1
        else:
            print(f"PERMERROR  {d}: mailguard={mine.permerror!r} pyspf={result} ({expl})")
        if not theirs_perm and not mine.permerror:
            counted += 1
            if mine.lookups == lookups:
                count_agree += 1
            else:
                print(f"LOOKUPS    {d}: mailguard={mine.lookups} pyspf={lookups}")
    perms = sum(1 for _, (m, r, _, _) in compared if r == "permerror")
    skipped = sum(1 for _, r, e in rows if not r and e)
    print(f"\n{len(domains)} domains, {len(compared)} with SPF compared ({skipped} skipped on DNS errors), "
          f"{perms} permerror per pyspf")
    print(f"permerror verdict agrees: {perm_agree}/{len(compared)}")
    print(f"lookup count agrees:      {count_agree}/{counted}")
    return 0 if perm_agree == len(compared) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
