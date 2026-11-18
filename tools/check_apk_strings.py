#!/usr/bin/env python3
"""Search the classes*.dex of an APK for byte strings. No Android tooling needed.

    python tools/check_apk_strings.py app-foss-release.apk --absent ОТПРАВЛЕНО ПОЛУЧЕНО anon_token отпечат
    python tools/check_apk_strings.py app-foss-debug.apk   --present ОТПРАВЛЕНО ПОЛУЧЕНО anon_token отпечат

Exit 0 if every --absent string is absent and every --present string is present,
1 otherwise. Strings are matched as UTF-8 bytes (dex stores strings as MUTF-8,
which is identical for everything that is not U+0000 or a supplementary
character). Used by docs/RELEASE_CHECKLIST.md: the S14-1 leak (release APK
writing 'who messaged whom' to the device log) was found by exactly this kind of
search on the published artifact, not by reading the source.
"""
import argparse
import re
import sys
import zipfile


def main():
    p = argparse.ArgumentParser()
    p.add_argument("apk")
    p.add_argument("--absent", nargs="*", default=[])
    p.add_argument("--present", nargs="*", default=[])
    a = p.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    with zipfile.ZipFile(a.apk) as z:
        dexes = sorted(n for n in z.namelist() if re.fullmatch(r"classes\d*\.dex", n))
        if not dexes:
            sys.exit("no classes*.dex in " + a.apk)
        blobs = {n: z.read(n) for n in dexes}
    print(f"{a.apk}: {len(dexes)} dex file(s): {', '.join(dexes)}")
    bad = 0
    for kind, strings in (("absent", a.absent), ("present", a.present)):
        for s in strings:
            n = sum(b.count(s.encode("utf-8")) for b in blobs.values())
            ok = (n == 0) if kind == "absent" else (n > 0)
            print(f"  [{'OK' if ok else 'FAIL'}] expected {kind}: {s!r} -> {n} occurrence(s)")
            bad += not ok
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
