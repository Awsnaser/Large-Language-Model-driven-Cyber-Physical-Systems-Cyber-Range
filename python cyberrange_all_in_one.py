#!/usr/bin/env python3
"""Compatibility wrapper for the historical Version 1 entry-point filename.

Use ``python cyberrange.py`` or the installed ``cps-cyberrange`` command for Version 2.
"""
import cyberrange as _implementation

globals().update({name: getattr(_implementation, name) for name in dir(_implementation) if not name.startswith("__")})
__version__ = _implementation.__version__

if __name__ == "__main__":
    _implementation.main()
