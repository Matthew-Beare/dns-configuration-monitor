"""Operator-initiated SSH checks and backups. SSH host keys are never auto-trusted."""
from __future__ import annotations
import argparse
import ipaddress
import os
from pathlib import Path
import re
import subprocess
import sys

LOGIN=re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')
SERVICE='named'
ZONE_RE=re.compile(r'^/etc/bind/zones/db\.[A-Za-z0-9][A-Za-z0-9.-]{0,120}$')

def destination(user,host):
    if not LOGIN.fullmatch(user):raise ValueError('Unsafe user name')
    addr=ipaddress.ip_address(host)
    if addr.is_multicast or addr.is_unspecified:raise ValueError('Unsafe destination')
    return f'{user}@{addr.compressed}'

def ssh_command(user,host,*words):
    return ['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
            '-o','ConnectTimeout=5','--',destination(user,host),*words]

def invoke(user,host,*words,accepted_codes=(0,)):
    cmd=ssh_command(user,host,*words)
    result=subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          timeout=20,check=False)
    if result.returncode not in accepted_codes:
        raise RuntimeError(f'SSH operation failed with exit code {result.returncode}')
    return result.stdout

# Backups can contain internal DNS data, so their destination is fixed to
# the ignored private-output/ directory. Never accept an arbitrary path.
BACKUP_ROOT = Path(__file__).resolve().parents[1] / 'private-output'


def backup_zone(user,host,output,zone):
    if not isinstance(zone,str) or not ZONE_RE.fullmatch(zone) or '..' in zone:
        raise ValueError('Zone must be an explicit /etc/bind/zones/db.<name> path')
    candidate = Path(output)
    if (candidate.is_absolute() or len(candidate.parts) != 2
            or candidate.parts[0] != 'private-output'
            or candidate.name in ('', '.', '..')):
        raise ValueError('Backup output must be private-output/<filename>')
    if BACKUP_ROOT.is_symlink():
        raise ValueError('Backup directory must not be a symbolic link')
    dest = BACKUP_ROOT / candidate.name
    if dest.is_symlink():
        raise ValueError('Backup output must not be a symbolic link')
    if dest.exists():
        raise FileExistsError('Refusing to overwrite existing backup')

    data=invoke(user,host,'sudo','-n','cat',zone)
    if not data.strip():
        raise RuntimeError('Remote zone file empty')
    BACKUP_ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
    if BACKUP_ROOT.is_symlink():
        raise ValueError('Backup directory must not be a symbolic link')
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    fd = os.open(dest, flags, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write(data)
    return dest

def restart_named(user,host):
    before=invoke(user,host,'systemctl','is-active',SERVICE,accepted_codes=(0,3)).strip()
    if before=='active':return ('active','active')
    invoke(user,host,'sudo','-n','systemctl','restart',SERVICE)
    after=invoke(user,host,'systemctl','is-active',SERVICE,accepted_codes=(0,3)).strip()
    if after!='active':raise RuntimeError('Service restart did not produce an active service')
    return before,after

def main():
    p=argparse.ArgumentParser(description='Operator-approved remote DNS service operations')
    p.add_argument('action',choices=['backup','restart'])
    p.add_argument('--host',required=True,help='Explicit trusted IP (not a domain name)')
    p.add_argument('--user',required=True)
    p.add_argument('--output',default='private-output/dns-zone-backup.txt')
    p.add_argument('--zone',help='Explicit BIND zone path for backup, e.g. /etc/bind/zones/db.example.test')
    p.add_argument('--confirm-live',action='store_true',help='Required before running SSH')
    a=p.parse_args()
    if not a.confirm_live:p.error('Live SSH operations require --confirm-live')
    if a.action=='backup':
        if not a.zone:p.error('A verified --zone is required for backup')
        print('Private backup created:',backup_zone(a.user,a.host,a.output,a.zone))
    else:print('DNS service status:',restart_named(a.user,a.host))

if __name__=='__main__':main()
