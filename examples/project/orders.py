def lookup_order(params, database):
    order_id = params["order_id"]
    return database.fetch(order_id)
