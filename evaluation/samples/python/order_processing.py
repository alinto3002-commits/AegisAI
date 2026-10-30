def process_order(order_data: dict):
    # Deep nesting smell and bare except
    try:
        if order_data:
            if "items" in order_data:
                if len(order_data["items"]) > 0:
                    for item in order_data["items"]:
                        if item.get("valid"):
                            if item.get("price", 0) > 0:
                                print(f"Valid item: {item['name']}")
    except:
        pass
