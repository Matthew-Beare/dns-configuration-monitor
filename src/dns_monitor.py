"""Compare DNS observations against an expected baseline without changing hosts."""
from __future__ import annotations
from dataclasses import dataclass, asdict
import ipaddress
import json
import re
from pathlib import Path

NAME=re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$')

def ips(value):
    if not isinstance(value,list):raise ValueError('Resolver values must be lists')
    return frozenset(str(ipaddress.ip_address(x)) for x in value)

@dataclass(frozen=True)
class Event:
    action:str
    device:str
    observed:list[str]
    expected:list[str]

    def as_dict(self):return asdict(self)

class DNSMonitor:
    def __init__(self,active=None):self.active=dict(active or {})

    def process(self,devices):
        if not isinstance(devices,list):raise ValueError('devices must be an array')
        updates=[];seen=set()
        for item in devices:
            if not isinstance(item,dict):raise ValueError('Observation must be an object')
            name=item.get('name');address=item.get('address');online=item.get('reachable')
            if not isinstance(name,str) or not NAME.fullmatch(name) or name in seen:
                raise ValueError('Invalid or duplicate device name')
            seen.add(name)
            ipaddress.ip_address(address)
            if online is not None and type(online) is not bool:raise ValueError('reachable must be true, false, or null')
            expected=ips(item.get('expected_dns'))
            if not expected:raise ValueError('Expected DNS cannot be empty')
            observed_raw=item.get('observed_dns')
            if online is not True and observed_raw is not None:raise ValueError('DNS sample needs reachability')
            observed=ips(observed_raw) if observed_raw is not None else None
            updates.append((name,expected,observed))
        events=[]
        for name,expected,observed in updates:
            if observed is None:continue  # Cannot resolve missing data.
            if observed!=expected and name not in self.active:
                self.active[name]=True
                events.append(Event('opened',name,sorted(observed),sorted(expected)))
            elif observed==expected and name in self.active:
                del self.active[name]
                events.append(Event('resolved',name,sorted(observed),sorted(expected)))
        return events

def run_replay(path):
    samples=json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(samples,list):raise ValueError('Expected list of sweeps')
    m=DNSMonitor();rows=[]
    for i,s in enumerate(samples,1):
        e=m.process(s['devices']);rows.append({'sweep':i,'events':[v.as_dict() for v in e], 'open_incidents':len(m.active)})
    return rows
