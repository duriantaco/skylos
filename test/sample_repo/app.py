import os
import sys
import json  # Unused import
import logging
from .sample_repo.routes import create_app

def main():
    """Run the application"""
    app = create_app()
    app.run()

if __name__ == "__main__":
    main()