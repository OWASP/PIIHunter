"""
Setup script for PII Scanner.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="pii-scanner",
    version="0.1.0",
    description="Internal PII discovery tool for PostgreSQL databases",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Your Organization",
    author_email="security@yourorg.com",
    url="https://github.com/yourorg/pii-scanner",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "psycopg2-binary>=2.9.9",
        "presidio-analyzer>=2.2.33",
        "presidio-anonymizer>=2.2.33",
        "spacy>=3.7.0",
        "click>=8.1.7",
        "python-dotenv>=1.0.0",
        "pydantic>=2.5.0",
        "pydantic-settings>=2.1.0",
        "structlog>=24.1.0",
        "colorama>=0.4.6",
        "requests>=2.31.0",
    ],
    entry_points={
        "console_scripts": [
            "pii-scanner=pii_scanner.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Database",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
