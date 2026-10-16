"""
Vercel Entry Point
Ye file Vercel ko batati hai ki FastAPI app kahan hai.
Actual app: web/app.py
"""

import os
import sys

# ============================================================
# VERCEL PATH SETUP
# ============================================================
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(ROOT_DIR, 'src')
WEB_DIR = os.path.join(ROOT_DIR, 'web')

# Saare paths add karo
for path in [SRC_DIR, WEB_DIR, ROOT_DIR]:
    if path not in sys.path:
        sys.path.insert(0, path)

# ============================================================
# IMPORT FASTAPI APP
# ============================================================
from web.app import app

# Vercel is `app` ko dhundhta hai
__all__ = ['app']