from __future__ import annotations

import shutil


def get_terminal_width(min_width: int = 20, max_width: int = 120) -> int:
    try:
        size = shutil.get_terminal_size(fallback=(80, 24))
        width = size.columns
        if width < 30:
            return max(min_width, width - 2)
        return max(min_width, min(width, max_width))
    except Exception:
        return 80
