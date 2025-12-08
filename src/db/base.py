"""
Base declarative class for SQLAlchemy models.

This file exists separately to avoid circular imports between setup.py and models.py
"""

from sqlalchemy.orm import declarative_base

Base = declarative_base()
