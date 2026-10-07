import json
import random
from datetime import datetime, timedelta, timezone

from .ingest import entity_id
from .schemas import ResourceContext
from .storage import Store


def generate_demo(seed: int = 17, variant: str = "positive") -> tuple[dict[str, list[dict]], list[dict]]:
    if variant not in {"positive", "benign", "missing-transfer"}:
        raise ValueError("unknown demo variant")
    rng = random.Random(seed)
    families = {name: [] for name in ("auth", "file", "device", "network")}
    users = rng.sample(range(1, 31), 3)
    devices = rng.sample(range(1, 21), 4)
    apps = rng.sample(range(1, 7), 2)
    start = datetime(2026, 1, 1, 9, tzinfo=timezone.utc)

    def add(family, time, action, user, device, **fields):
        families[family].append({"timestamp": time.isoformat(), "action": action,
            "user_id": f"u{user}", "device_id": f"d{device}", **fields})

    for day in range(5):
        for index, user in enumerate(users):
            time = start + timedelta(days=day, minutes=index * 6)
            add("auth", time, "login_success", user, devices[index], app_id=f"app{apps[0]}", src_ip="10.0.0.5")
            for offset in range(3):
                add("file", time + timedelta(minutes=1 + offset), "file_read", user, devices[index],
                    resource_id=f"work-{index}-{offset}", file_path=f"/work/document-{offset}.txt", bytes_read=rng.randint(100, 3000))
            add("network", time + timedelta(minutes=5), "network_connect", user, devices[index],
                dst_ip="192.0.2.10", bytes_sent=rng.randint(10, 800))
    time = start + timedelta(days=6, minutes=rng.randint(10, 20))
    user, device = users[0], devices[3]
    resource, usb = f"resource-{rng.randint(100, 999)}", f"media-{rng.randint(1, 90)}"
    add("auth", time, "login_success", user, device, app_id=f"app{apps[1]}", src_ip="10.0.0.5")
    if variant != "benign":
        add("file", time + timedelta(minutes=4), "file_read", user, device,
            resource_id=resource, file_path="/data/quarterly.csv", bytes_read=125000)
    add("device", time + timedelta(minutes=7), "usb_mount", user, device, removable_device_id=usb)
    if variant == "positive":
        add("file", time + timedelta(minutes=10), "file_copy_to_usb", user, device,
            resource_id=resource, file_path="/data/quarterly.csv", removable_device_id=usb,
            destination_type="removable_media", bytes_written=125000)
    resources = [{"resource_id": entity_id("synthetic-office", "file", resource), "sensitive": True,
                  "provenance": "Seeded synthetic asset catalog; operator-supplied trusted context, not log text",
                  "effective_from": "2026-01-01T00:00:00+00:00", "effective_until": None}]
    return families, resources


def load_demo(store: Store, seed: int = 17, variant: str = "positive") -> str:
    files, resources = generate_demo(seed, variant)
    dataset_id = store.create_dataset(f"Synthetic {variant} · seed {seed}", "synthetic-office", "synthetic", seed)
    for family, records in files.items():
        content = ("\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n").encode()
        store.ingest(dataset_id, content, f"{family}.jsonl", family, family)
    store.set_resources(dataset_id, [ResourceContext.model_validate(r) for r in resources])
    return dataset_id
