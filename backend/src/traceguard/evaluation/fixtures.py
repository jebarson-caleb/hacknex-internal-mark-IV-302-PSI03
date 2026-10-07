"""Seeded chronological benchmark observations and separate evaluation labels."""
import json
import random
from datetime import datetime, timedelta, timezone

from ..ingest import entity_id
from ..schemas import ResourceContext
from ..storage import Store

ENVIRONMENT = "synthetic-office"


def generate_partition(seed: int, start_day: int, days: int, *, users: int = 30, event_count: int = 1000,
                       attacks: bool = False) -> tuple[dict, list[dict], list[dict]]:
    if not 3 <= users <= 100 or event_count < days*users*5:
        raise ValueError("profile needs 3..100 users and at least 5 events per user/day")
    rng = random.Random(seed)
    files = {family:[] for family in ("auth","file","device","network")}
    base = datetime(2026,1,1,tzinfo=timezone.utc)
    contexts,labels = [],[]
    sequence = 0

    def add(family,time,action,user,device,**fields):
        nonlocal sequence
        sequence += 1
        vendor = f"record-{sequence:06d}"
        row = {"source_event_id":vendor,"timestamp":time.isoformat(),"action":action,
               "user_id":f"u{user}","device_id":f"d{device}",**fields}
        files[family].append(row)
        return vendor

    budget = event_count // (days*users)
    for day in range(start_day,start_day+days):
        for user in range(users):
            device = user%20; app = user%6
            hour = 8+user%9  # Includes routine shift variation, frozen across seeds.
            time = base+timedelta(days=day-1,hours=hour,minutes=rng.randint(0,4))
            add("auth",time,"login_success",user,device,app_id=f"app{app}",src_ip="10.0.0.5")
            for offset in range(budget-2):
                resource = f"assigned-{user}-{offset%3}"
                add("file",time+timedelta(seconds=30+offset*10),"file_read",user,device,
                    resource_id=resource,file_path=f"/work/{resource}.csv",bytes_read=rng.randint(500,25000))
            add("network",time+timedelta(minutes=8),"network_connect",user,device,dst_ip="192.0.2.10",bytes_sent=rng.randint(100,8000))
    # Ordinary USB/backup activity: established identities, assigned resources.
    day = start_day+days-1
    time = base+timedelta(days=day-1,hours=8,minutes=9)
    add("device",time,"usb_mount",0,0,removable_device_id="routine-media")
    add("file",time+timedelta(minutes=1),"file_copy_to_usb",0,0,resource_id="assigned-0-0",
        removable_device_id="routine-media",destination_type="removable_media",bytes_written=20000)
    # New employee: absent frozen history, not a automatic high-risk account.
    add("auth",time+timedelta(minutes=2),"login_success",users+1,2,app_id="app2",src_ip="10.0.0.5")
    # VPN changes do not establish a new actor or anomalous device.
    add("auth",time+timedelta(minutes=3),"login_success",0,0,app_id="app0",src_ip="198.51.100.20")
    if attacks:
        actor = rng.randrange(1,users)
        device = (actor%20+1)%20
        time = base+timedelta(days=start_day+days-2,hours=3,minutes=rng.randint(0,4))
        resource = f"restricted-{rng.randrange(100,999)}"; media=f"media-{rng.randrange(100)}"
        contexts.append({"resource_id":entity_id(ENVIRONMENT,"file",resource),"sensitive":True,
            "provenance":"Seeded synthetic asset catalog, separate operator context",
            "effective_from":"2026-01-01T00:00:00Z","effective_until":None})
        auth = add("auth",time,"login_success",actor,device,app_id=f"app{(actor%6+1)%6}",src_ip="10.0.0.5")
        read = add("file",time+timedelta(minutes=2),"file_read",actor,device,resource_id=resource,file_path="/data/quarterly.csv",bytes_read=rng.randint(300000,2000000))
        mount = add("device",time+timedelta(minutes=3),"usb_mount",actor,device,removable_device_id=media)
        copy = add("file",time+timedelta(minutes=5),"file_copy_to_usb",actor,device,resource_id=resource,
                   removable_device_id=media,destination_type="removable_media",bytes_written=rng.randint(300000,2000000))
        labels.append({"scenario_id":f"episode-{seed}","user_id":entity_id(ENVIRONMENT,"user",f"u{actor}"),
            "device_id":entity_id(ENVIRONMENT,"endpoint",f"d{device}"),
            "stages":{"authentication":auth,"collection":read,"transfer":copy},"context":[mount],
            "order_constraints":[[auth,read],[read,copy],[mount,copy]]})
        # Missing-copy confounder with another established actor; partial only.
        user=(actor+1)%users; endpoint=(user%20+2)%20
        incomplete=time+timedelta(hours=2)
        add("auth",incomplete,"login_success",user,endpoint,app_id="app5",src_ip="10.0.0.5")
        add("file",incomplete+timedelta(minutes=2),"file_read",user,endpoint,resource_id=resource,bytes_read=200000)
        add("device",incomplete+timedelta(minutes=3),"usb_mount",user,endpoint,removable_device_id="other-media")
    return files,contexts,labels


def load_partition(store: Store, files: dict, contexts: list[dict], labels: list[dict], name: str, seed: int) -> tuple[str,list[dict]]:
    dataset = store.create_dataset(name,ENVIRONMENT,"synthetic",seed)
    for family,rows in files.items():
        content = ("\n".join(json.dumps(row,sort_keys=True) for row in rows)+"\n").encode()
        store.ingest(dataset,content,f"{family}.jsonl",family,family)
    store.set_resources(dataset,[ResourceContext.model_validate(c) for c in contexts])
    event_ids = {e.source_event_id:e.event_id for e in store.events(dataset)}
    mapped = []
    for label in labels:
        mapped.append({**label,"stages":{k:event_ids[v] for k,v in label["stages"].items()},
                       "context":[event_ids[eid] for eid in label["context"]],
                       "order_constraints":[[event_ids[a],event_ids[b]] for a,b in label["order_constraints"]]})
    return dataset,mapped


def load_chronological_demo(store: Store, seed: int = 17, users: int = 6, events: int = 1200) -> tuple[dict,list[dict]]:
    # Defaults are small for UI/tests; benchmark CLI has the 20k/30-user profile.
    train,_ = load_partition(store,*generate_partition(seed,1,14,users=users,event_count=events//2),"Synthetic days 1–14",seed)
    cal,_ = load_partition(store,*generate_partition(seed+1,15,7,users=users,event_count=events//4),"Synthetic days 15–21 benign",seed+1)
    test,labels = load_partition(store,*generate_partition(seed+2,22,7,users=users,event_count=events//4,attacks=True),"Synthetic days 22–28 held-out",seed+2)
    return {"training":store.dataset(train),"calibration":store.dataset(cal),"test":store.dataset(test)},labels
