#!/usr/bin/env python3
"""Backwards-compatible entry point — the real package lives in ipfindx/.

Keep this module import-light: build tools (setuptools, sdist finders)
may resolve the name ``ipfindx`` against THIS file before the ipfindx/
package, so any top-level import here can shadow or break packaging.
"""
if __name__ == "__main__":
    from ipfindx.cli import main

    raise SystemExit(main())
