import unittest
from unittest.mock import patch
from pathlib import Path
from tempfile import TemporaryDirectory
from src.dns_monitor import DNSMonitor,run_replay
from src.ssh_actions import ssh_command,backup_zone,restart_named

class DNSTests(unittest.TestCase):
    def test_lifecycle(self):
        self.assertEqual([0,1,0,1],[len(s['events']) for s in run_replay('examples/dns_sweeps.json')])
    def test_state_is_unchanged_after_rejected_input(self):
        m=DNSMonitor()
        with self.assertRaises(ValueError):m.process([{'name':'DNS1','address':'192.0.2.53','reachable':True,'expected_dns':['not-ip'],'observed_dns':['192.0.2.53']}])
        self.assertEqual({},m.active)
    def test_ssh_strict_hosts(self):
        cmd=ssh_command('operator','192.0.2.53','systemctl','is-active','named')
        self.assertIn('StrictHostKeyChecking=yes',cmd)
        self.assertIn('BatchMode=yes',cmd)
        with self.assertRaises(ValueError):ssh_command('-oProxyCommand=x','192.0.2.53','test')
        with self.assertRaises(ValueError):ssh_command('operator','bad.example.com','test')
    @patch('src.ssh_actions.invoke',return_value='example.test. 3600 IN A 192.0.2.10\n')
    def test_backup_is_private_no_overwrite(self,invoke):
        with TemporaryDirectory() as tmp:
            private_root = Path(tmp)/'private-output'
            with patch('src.ssh_actions.BACKUP_ROOT', private_root):
                output = 'private-output/backup.txt'
                result=backup_zone('operator','192.0.2.53',output,'/etc/bind/zones/db.example.test')
                self.assertEqual(private_root/'backup.txt',result)
                self.assertIn('192.0.2.10',result.read_text())
                self.assertEqual(0o600, result.stat().st_mode & 0o777)
                with self.assertRaises(FileExistsError):
                    backup_zone('operator','192.0.2.53',output,'/etc/bind/zones/db.example.test')
                for bad in (str(Path(tmp)/'leak.txt'), '../leak.txt', 'docs/leak.txt', 'private-output/../leak.txt'):
                    with self.subTest(output=bad), self.assertRaises(ValueError):
                        backup_zone('operator','192.0.2.53',bad,'/etc/bind/zones/db.example.test')
        self.assertEqual(1,invoke.call_count)
    @patch('src.ssh_actions.invoke',side_effect=['inactive','','active'])
    def test_restart_verifies_actual_state(self,invoke):
        self.assertEqual(('inactive','active'),restart_named('operator','192.0.2.53'))
        self.assertEqual(3,invoke.call_count)
    @patch('src.ssh_actions.invoke',side_effect=['inactive','','inactive'])
    def test_restart_failure(self,invoke):
        with self.assertRaises(RuntimeError):restart_named('operator','192.0.2.53')

if __name__=='__main__':unittest.main()
