"""Compatibility entry point for the portable scan runner."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from runner.run_scan import main

if __name__ == '__main__':
    raise SystemExit(main())
