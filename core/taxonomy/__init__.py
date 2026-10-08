"""Failure taxonomy (14 categories) and the deterministic pre-classifier."""

from core.taxonomy.categories import SUBCATEGORIES, FailureCategory, is_valid_subcategory

__all__ = ["FailureCategory", "SUBCATEGORIES", "is_valid_subcategory"]
