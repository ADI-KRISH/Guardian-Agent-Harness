import sys
import threading
import time
import unittest
from unittest.mock import patch
from guardian import tunnel


class TunnelTests(unittest.TestCase):
    def tearDown(self):
        tunnel.stop()

    def wait_for(self, wanted, timeout=3):
        until = time.monotonic()+timeout
        while time.monotonic()<until:
            state=tunnel.status()
            if state['status']==wanted: return state
            time.sleep(.01)
        self.fail(tunnel.status())

    def test_provider_urls_ansi_json_and_legacy(self):
        for host in ('abc.lhr.life','abc.app.lhr.life','abc.localhost.run'):
            value='\x1b[2;1H{"url":"https://'+host+'"}\x1b[39m'
            self.assertEqual(tunnel.extract_url(value,'localhost.run'),'https://'+host)
        self.assertIsNone(tunnel.extract_url('https://abc.lhr.life.evil.example','localhost.run'))
        self.assertIsNone(tunnel.extract_url('https://admin.localhost.run','localhost.run'))
        self.assertEqual(tunnel.extract_url('https://a-b.trycloudflare.com','cloudflared'),'https://a-b.trycloudflare.com')

    def test_nonblocking_start_and_repeat_do_not_deadlock(self):
        done=threading.Event()
        with patch.object(tunnel,'detect',return_value=('localhost.run','ssh')), patch.object(tunnel,'_run',side_effect=lambda *args:done.wait(2)):
            started=time.monotonic()
            self.assertEqual(tunnel.start()['status'],'starting')
            result=[]
            worker=threading.Thread(target=lambda:result.append(tunnel.start()),daemon=True)
            worker.start();worker.join(.5)
            done.set()
            self.assertFalse(worker.is_alive(),'Repeated start deadlocked')
            self.assertTrue(result[0]['ok'])
            self.assertLess(time.monotonic()-started,1)

    def test_reads_url_without_newline(self):
        script="import os,time; os.write(1,b'\\x1b[2;1Hhttps://abc.app.lhr.'); time.sleep(.1); os.write(1,b'life\\x1b[39m'); time.sleep(4)"
        with patch.object(tunnel,'detect',return_value=('localhost.run','ssh')), patch.object(tunnel,'command',return_value=[sys.executable,'-c',script]):
            tunnel.start()
            state=self.wait_for('running')
            self.assertEqual(state['url'],'https://abc.app.lhr.life')
            self.assertNotIn('\x1b',state['log'])

    def test_exit_keeps_error_and_log(self):
        with patch.object(tunnel,'detect',return_value=('localhost.run','ssh')), patch.object(tunnel,'command',return_value=[sys.executable,'-c',"import sys;sys.stderr.write('DNS lookup failed');sys.exit(2)"]):
            tunnel.start();state=self.wait_for('error')
            self.assertIn('DNS lookup failed',state['error'])
            self.assertIn('code 2',state['error'])
            self.assertIsNone(state['url'])

    def test_silent_process_times_out_and_is_reaped(self):
        with patch.object(tunnel,'STARTUP_TIMEOUT',.2), patch.object(tunnel,'detect',return_value=('localhost.run','ssh')), patch.object(tunnel,'command',return_value=[sys.executable,'-c','import time;time.sleep(10)']):
            tunnel.start();state=self.wait_for('error')
            self.assertIn('within',state['error'])
            time.sleep(.2)
            self.assertIsNone(tunnel._state['process'])

    def test_stopped_worker_cannot_overwrite_new_state(self):
        old=tunnel._generation
        tunnel.stop()
        self.assertFalse(tunnel._update(old,status='running',url='https://stale.lhr.life'))
        self.assertEqual(tunnel.status()['status'],'stopped')

    def test_ssh_is_noninteractive_and_requests_machine_output(self):
        args=tunnel.command('localhost.run','ssh',8787)
        self.assertIn('BatchMode=yes',args)
        self.assertIn('ExitOnForwardFailure=yes',args)
        self.assertIn('80:127.0.0.1:8787',args)
        self.assertEqual(args[-3:],['--','--output','json'])

    def test_missing_tool_is_explicit(self):
        with patch.object(tunnel,'detect',return_value=(None,None)):
            self.assertEqual(tunnel.start()['status'],'not_installed')

    def test_invalid_port(self):
        with self.assertRaises(ValueError):tunnel.start(0)
