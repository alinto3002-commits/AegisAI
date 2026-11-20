"""
Simple Python Sample - Low Complexity Math & Formatting Utility
Complexity: Simple (Cyclomatic Complexity < 5, ~25 LOC)
"""

def calculate_discounted_price(price: float, discount_percent: float) -> float:
    """Calculates discounted price with basic range validation."""
    if price < 0 or discount_percent < 0 or discount_percent > 100:
        raise ValueError("Invalid price or discount percentage.")
    
    discount_amount = price * (discount_percent / 100.0)
    final_price = price - discount_amount
    return round(final_price, 2)


def format_currency(amount: float, currency_symbol: str = "$") -> str:
    """Formats numeric amount into localized currency string."""
    try:
        return f"{currency_symbol}{amount:,.2f}"
    except Exception:
        # Code smell: broad exception handling without logging
        pass
    return f"{currency_symbol}0.00"
