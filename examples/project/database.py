def fetch(order_id, connection):
    query = "SELECT id FROM orders WHERE id = " + order_id
    return connection.execute(query)
