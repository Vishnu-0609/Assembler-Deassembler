"""
Vercel serverless function wrapper for FastAPI app
"""
import sys
import os

# Get the project root directory
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backend_path = os.path.join(project_root, 'backend')

# Add backend directory to Python path
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

# Import the FastAPI app from backend
try:
    from main import app
except ImportError:
    # Fallback: add parent directory to path
    sys.path.insert(0, project_root)
    from backend.main import app

# Export as handler for Vercel
# Vercel Python runtime automatically wraps FastAPI apps
handler = app
