from threading import Lock

MOCK_LOCK = Lock()
MOCK_DATA = {
    "products": [
        {"id": 1, "name": "Ноутбук", "owner_id": 1},
        {"id": 2, "name": "Мышка", "owner_id": 2},
    ],
    "orders": [
        {"id": 1, "name": "Заказ #1001", "owner_id": 1},
        {"id": 2, "name": "Заказ #1002", "owner_id": 2},
    ],
}
MOCK_COUNTER = {"products": 2, "orders": 2}


def list_items(resource: str) -> list[dict]:
    with MOCK_LOCK:
        return [item.copy() for item in MOCK_DATA[resource]]


def get_item(resource: str, item_id: int) -> dict | None:
    with MOCK_LOCK:
        for item in MOCK_DATA[resource]:
            if item["id"] == item_id:
                return item.copy()
    return None


def create_item(resource: str, name: str, owner_id: int, description: str | None) -> dict:
    with MOCK_LOCK:
        MOCK_COUNTER[resource] += 1
        item = {"id": MOCK_COUNTER[resource], "name": name, "owner_id": owner_id}
        if description:
            item["description"] = description
        MOCK_DATA[resource].append(item)
        return item.copy()


def update_item(resource: str, item_id: int, name: str, description: str | None) -> dict | None:
    with MOCK_LOCK:
        for item in MOCK_DATA[resource]:
            if item["id"] == item_id:
                item["name"] = name
                if description is not None:
                    item["description"] = description
                return item.copy()
    return None


def delete_item(resource: str, item_id: int) -> bool:
    with MOCK_LOCK:
        before = len(MOCK_DATA[resource])
        MOCK_DATA[resource] = [item for item in MOCK_DATA[resource] if item["id"] != item_id]
        return len(MOCK_DATA[resource]) < before
