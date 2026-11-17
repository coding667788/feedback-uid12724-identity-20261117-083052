"""隔离模式（python -I）包装入口。

``python -I`` 会忽略 PYTHONPATH 且不把 cwd 加入 sys.path，无法直接
``-m solution``；自动化测试在隔离模式下运行本包装器：

    python -I run_solution.py --input cases/cases.json --output result.json

普通使用仍以题目要求的 ``python -m solution`` 为准。
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from solution.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
