"""支持 ``python -m solution --input cases.json --output result.json``。"""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
