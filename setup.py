"""Setup configuration for AuthLib."""

from setuptools import setup, find_packages

setup(
    name="agent-auth",
    version="1.0.0",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "sqlalchemy>=2.0.0,<3.0.0",
        "PyJWT>=2.8.0",
        "bcrypt>=4.1.0",
        "pydantic>=2.5.0",
        "python-dotenv>=1.0.0",
        "psycopg2-binary>=2.9.11",
        "cryptography>=42.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "isort>=5.12.0",
        ],
        "fastapi": [
            "fastapi>=0.104.0",
            "uvicorn>=0.24.0",
        ],
        "flask": [
            "flask>=3.0.0",
        ],
        "psycopg": [
            "psycopg2-binary>=2.9.11",
        ],
    },
    author="AuthLib Contributors",
    author_email="support@authlib.dev",
    description="A scalable, framework-agnostic Python authentication library with JWT, user registration, login, and password reset",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/MrunalHedau4102/agent-auth",
    project_urls={
        "Documentation": "https://github.com/MrunalHedau4102/agent-auth#readme",
        "Source": "https://github.com/MrunalHedau4102/agent-auth",
        "Issue Tracker": "https://github.com/MrunalHedau4102/agent-auth/issues",
        "Changelog": "https://github.com/MrunalHedau4102/agent-auth/blob/main/CHANGELOG.md",
    },
    download_url="https://github.com/MrunalHedau4102/agent-auth/releases",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security",
    ],
    keywords="authentication authorization jwt signup login password-reset oauth",
)
