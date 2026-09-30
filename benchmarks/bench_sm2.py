# -*- coding: utf-8 -*-
"""Benchmark JWT generation/verification speed across crypto backends.

The benchmark is backend-driven: SM2 and HMAC-SM3 are measured for every
installed backend (``pysmx`` / ``gmssl_pyx``). Results are printed to stdout
and (by default) written to a Markdown report.

Usage::

    python benchmarks/bench_sm2.py                 # print + write benchmarks/BENCHMARK.md
    python benchmarks/bench_sm2.py --no-md        # print only
    python benchmarks/bench_sm2.py --markdown out.md --runs 500
"""
import argparse
import json
import os
import platform
import sys
import time

# Make the repository root importable when run as a standalone script.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import snowland_jwt as jwt  # noqa: E402
from snowland_jwt import DEFAULT_SM2_UID, HS256_SM3  # noqa: E402
from snowland_jwt.algorithms import HMACSM3Algorithm  # noqa: E402


def _backend_installed(name):
    try:
        jwt.get_crypto_backend(name)
        return True
    except Exception:
        return False


def _bench(fn, runs):
    """Return (ops_per_sec, ms_per_op) after a short warm-up."""
    for _ in range(5):
        fn()
    t0 = time.perf_counter()
    for _ in range(runs):
        fn()
    secs = time.perf_counter() - t0
    return runs / secs, (secs / runs) * 1000.0


def _fmt_ver(ver):
    return ver if ver else "n/a"


def collect(runs):
    """Run all benchmarks and return a structured result dict."""
    priv, _pub = jwt.generate_key()
    payload = {"sub": "bench-user", "role": "admin", "iat": 1700000000}
    rows = []  # (group, label, ops, ms)

    sm2_backends = [n for n in ("pysmx", "gmssl_pyx") if _backend_installed(n)]
    for name in sm2_backends:
        alg = jwt.register_sm2(DEFAULT_SM2_UID, alg_name="SM2-B-" + name,
                               backend=name)
        ops, ms = _bench(lambda: jwt.encode(payload, priv, algorithm=alg), runs)
        rows.append(("SM2 encode", name, ops, ms))
        ops, ms = _bench(
            lambda: jwt.decode(jwt.encode(payload, priv, algorithm=alg),
                               _pub, algorithms=[alg]), runs)
        rows.append(("SM2 verify", name, ops, ms))

    hmac_backends = [n for n in ("pysmx", "gmssl_pyx") if _backend_installed(n)]
    for name in hmac_backends:
        alg = HMACSM3Algorithm(backend=name)
        ops, ms = _bench(lambda: alg.sign(b"bench-input", "bench-secret-key"),
                         runs)
        rows.append(("HMAC-SM3 sign", name, ops, ms))
    # Default (auto-selected) backend via the public API.
    ops, ms = _bench(
        lambda: jwt.encode(payload, "bench-secret-key", algorithm=HS256_SM3),
        runs)
    rows.append(("HMAC-SM3 encode", "default", ops, ms))

    env = {
        "python": platform.python_version(),
        "pysmx": _fmt_ver(_pkg_ver("pysmx")),
        "gmssl_pyx": _fmt_ver(_pkg_ver("gmssl_pyx")),
    }
    return {"env": env, "rows": rows, "runs": runs}


def _pkg_ver(name):
    try:
        from importlib.metadata import version, packages_distributions
    except Exception:
        return None
    try:
        return version(name)
    except Exception:
        pass
    # Fall back to the distribution that provides this top-level module
    # (e.g. ``pysmx`` is distributed as ``snowland-smx``).
    try:
        mod = name.split(".")[0]
        for dist_name in packages_distributions().get(mod, []):
            try:
                return version(dist_name)
            except Exception:
                continue
    except Exception:
        pass
    return None


def render_text(result):
    lines = []
    for group in sorted({r[0] for r in result["rows"]}):
        lines.append("\n%s:" % group)
        for r_group, label, ops, ms in result["rows"]:
            if r_group == group:
                lines.append("  %-16s %8.1f ops/s  %8.3f ms/op" % (label, ops, ms))
    return "\n".join(lines)


def render_markdown(result):
    env = result["env"]
    out = ["# snowland-jwt 性能基准 (Benchmark)", ""]
    out.append("- 环境: Python %s, pysmx %s, gmssl-pyx %s" % (
        env["python"], env["pysmx"], env["gmssl_pyx"]))
    out.append("- 测量: 每配置 warm-up 5 次 + %d 次取均值" % result["runs"])
    out.append("")
    groups = sorted({r[0] for r in result["rows"]})
    for group in groups:
        out.append("## %s" % group)
        out.append("")
        out.append("| Backend | ops/s | ms/op |")
        out.append("|---|---|---|")
        for r_group, label, ops, ms in result["rows"]:
            if r_group == group:
                out.append("| %s | %.1f | %.3f |" % (label, ops, ms))
        out.append("")
    return "\n".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(description="snowland-jwt backend benchmark")
    parser.add_argument("--runs", type=int, default=200,
                        help="iterations per configuration (after warm-up)")
    parser.add_argument("--markdown", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "BENCHMARK.md"),
        help="Markdown report output path")
    parser.add_argument("--no-md", action="store_true",
                        help="do not write the Markdown report")
    args = parser.parse_args(argv)

    result = collect(args.runs)
    print("环境: Python %s, pysmx %s, gmssl-pyx %s" % (
        result["env"]["python"], result["env"]["pysmx"],
        result["env"]["gmssl_pyx"]))
    print(render_text(result))

    if not args.no_md:
        path = os.path.abspath(args.markdown)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(result))
        print("\nMarkdown report written to: %s" % path)


if __name__ == "__main__":
    main()
