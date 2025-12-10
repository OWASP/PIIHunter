"""
Entry point for running the PII scanner as a module.

Usage: python -m pii_scanner.cli <command>
"""

from .cli import main

if __name__ == "__main__":
    main()
