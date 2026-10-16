"""
Vercel Entry Point
Ye file Vercel ko batati hai ki FastAPI app kahan hai.
Actual app: web/app.py

IMPORTANT: Ye file sirf Vercel entry point hai.
Yahan koi business logic nahi honi chahiye.
"""

import os
import sys

# ============================================================
# VERCEL PATH SETUP
# ============================================================
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(ROOT_DIR, 'src')
WEB_DIR = os.path.join(ROOT_DIR, 'web')

# Saare paths add karo — config, scanner, network_scanner ke liye
for path in [SRC_DIR, WEB_DIR, ROOT_DIR]:
    if path not in sys.path:
        sys.path.insert(0, path)

# ============================================================
# IMPORT FASTAPI APP FROM web/app.py
# ============================================================
from web.app import app

# Vercel is `app` ko dhundhta hai
__all__ = ['app']