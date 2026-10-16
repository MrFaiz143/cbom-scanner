import os
import sys

# Path setup
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT_DIR, 'src'))
sys.path.insert(0, os.path.join(ROOT_DIR, 'web'))
sys.path.insert(0, ROOT_DIR)

# Import FastAPI app from web/app.py
from web.app import app

__all__ = ['app']