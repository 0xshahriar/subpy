"""Allow ``python -m subpy``.

Signal handling must be armed before the heavy imports in :mod:`subpy.cli`,
so the real entry point lives in :mod:`subpy._startup`.
"""

import sys

from ._startup import main

if __name__ == "__main__":
    sys.exit(main())
