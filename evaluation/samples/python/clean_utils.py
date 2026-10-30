"""
Clean Utilities Module
Baseline clean file with no security vulnerabilities or code smells.
"""

def sanitize_text(text: str) -> str:
    """Safely strips leading and trailing whitespace."""
    if not text:
        return ""
    return text.strip()

def format_currency(amount: float, symbol: str = "$") -> str:
    """Formats numeric amount as currency string."""
    return f"{symbol}{amount:,.2f}"
