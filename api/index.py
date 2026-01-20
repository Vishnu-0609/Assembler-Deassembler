"""
Vercel serverless function wrapper for FastAPI app
"""
import sys
import os

# Add backend directory to path
backend_path = os.path.join(os.path.dirname(__file__), '..', 'backend')
sys.path.insert(0, os.path.abspath(backend_path))

# Import the FastAPI app
from backend.main import app

# Export as handler for Vercel
handler = app
