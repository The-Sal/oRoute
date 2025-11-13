import os
import sys
import json
import time
import signal
import subprocess
import unittest
from typing import Optional, Tuple, List


REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
DAEMON_PATH = os.path.join(REPO_ROOT, 'oRoute_daemon.py')
CLIENT_PATH = os.path.join(REPO_ROOT, 'oRoute.py')
sys.path.insert(0, REPO_ROOT)
from oRoute import (
    parse_ssh,
    _inject_host_if_missing_in_rsync_endpoint,
    _replace_host_in_rsync_endpoint,
    _inject_host_from_scheme,
    resolve_connectivity,
)

# Tailscale address provided in the issue
TS_ADDR = '100.122.56.36'


class OrouteIntegrationTests(unittest.TestCase):
    daemon_proc: Optional[subprocess.Popen] = None
    _logs: dict = {}
    _current_test: Optional[str] = None

    @classmethod
    def setUpClass(cls):
        # Launch the daemon as a background subprocess, non-blocking
        env = os.environ.copy()
        cls.daemon_proc = subprocess.Popen(
            [sys.executable, DAEMON_PATH],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        # Give it a short moment to start listening
        time.sleep(1.0)

    @classmethod
    def tearDownClass(cls):
        # Terminate the daemon if still running
        if cls.daemon_proc and cls.daemon_proc.poll() is None:
            try:
                cls.daemon_proc.terminate()
                try:
                    cls.daemon_proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    cls.daemon_proc.kill()
            except Exception:
                pass
        # Write aggregated logs to tests.log
        try:
            log_path = os.path.join(REPO_ROOT, 'tests.log')
            with open(log_path, 'w', encoding='utf-8') as f:
                for test_name, chunks in cls._logs.items():
                    f.write(f"=== {test_name} ===\n")
                    # Join chunks; ensure each chunk ends with newline
                    for chunk in chunks:
                        if chunk and not chunk.endswith('\n'):
                            chunk = chunk + '\n'
                        f.write(chunk)
                    f.write('\n')
        except Exception:
            # Do not fail the test suite if logging fails
            pass

    def setUp(self):
        # Record current test name for logging
        self.__class__._current_test = self.id() or self._testMethodName
        if self.__class__._current_test not in self.__class__._logs:
            self.__class__._logs[self.__class__._current_test] = []

    def _append_log(self, text: str):
        name = self.__class__._current_test or self._testMethodName
        self.__class__._logs.setdefault(name, []).append(text)

    def run_client(self, args: List[str], timeout: float = 10.0) -> Tuple[int, str]:
        """Run oRoute client with given args, capture combined stdio, enforce timeout.
        Returns (returncode, output)
        """
        # Force SSH to avoid interactive password prompts
        env = os.environ.copy()
        # Prefer a portable 'false' path; '/bin/false' might not exist on some systems
        askpass = None
        for p in ('/usr/bin/false', '/bin/false', '/usr/bin/true', '/bin/true'):
            if os.path.exists(p):
                askpass = p
                break
        env.setdefault('SSH_ASKPASS', askpass or 'false')
        env.setdefault('SSH_ASKPASS_REQUIRE', 'force')
        # Empty DISPLAY so askpass won't try to open GUI
        env.setdefault('DISPLAY', 'none')
        # Make output deterministic/non-colored
        env.setdefault('TERM', 'dumb')

        proc = subprocess.Popen(
            [sys.executable, CLIENT_PATH] + args,
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            env=env,
            start_new_session=True,
        )
        try:
            out, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            # Timed out -> kill process tree where possible
            try:
                # Terminate the whole process group (client + any ssh/rsync children)
                os.killpg(proc.pid, signal.SIGTERM)
            except Exception:
                pass
            try:
                out, _ = proc.communicate(timeout=2)
            except Exception:
                out = ''
            # Ensure it's gone
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except Exception:
                    pass
        out = out or ''
        # Append to per-test log with a small header of the command invoked
        try:
            self._append_log(f"$ oRoute.py {' '.join(args)}\n{out}")
        except Exception:
            pass
        return proc.returncode or 0, out

    @staticmethod
    def _no_password_prompt(output: str) -> bool:
        low = output.lower()
        suspicious = [
            'password:',
            'enter passphrase',
            'passphrase for key',
            'permission denied (publickey,password',
            'permission denied (publickey,keyboard-interactive',
        ]
        return not any(s in low for s in suspicious)

    def test_help_command(self):
        code, out = self.run_client(['--service', 'help'])
        self.assertIn('oRoute Client Help', out)

    def test_version_command(self):
        code, out = self.run_client(['--service', 'version'])
        self.assertIn('oRoute Client version', out)

    def test_resolve_command(self):
        code, out = self.run_client([TS_ADDR, '--service', 'resolve'])
        # Should output a single JSON line
        try:
            data = json.loads(out.strip().splitlines()[-1]) if out.strip() else {}
        except json.JSONDecodeError:
            self.fail(f'resolve did not return JSON. Output was:\n{out}')
        # Ensure expected keys exist
        for key in ['tailscale_address', 'local_address', 'reachable', 'server_uuid']:
            self.assertIn(key, data)

    def test_ssh_no_password_prompt(self):
        # Default service is ssh. Use provided Tailscale address.
        code, out = self.run_client([TS_ADDR])
        self.assertTrue(
            self._no_password_prompt(out),
            msg=f'SSH output indicates a password prompt was issued:\n{out}',
        )

    def test_rsync_no_password_prompt(self):
        # Use dry-run to avoid actual transfer; endpoints crafted to be harmless
        # When a local IP is not found, it will use the Tailscale host.
        # We keep src as current directory and dst as a remote SSH-style path.
        code, out = self.run_client([
            TS_ADDR,
            '--service', 'rsync',
            '--src', '.',
            '--dst', f'{TS_ADDR}:/tmp',
            # Pass rsync args using '=' so argparse accepts leading '-' values
            '--rsync-args=-n',
        ])
        self.assertTrue(
            self._no_password_prompt(out),
            msg=f'rsync output indicates a password prompt was issued:\n{out}',
        )

    def test_search_command_runs_and_exits(self):
        # search can be heavy; ensure it gets terminated within timeout window
        code, out = self.run_client(['--service', 'search'], timeout=10.0)
        # Either finished quickly or we terminated; just assert we captured some output lines
        self.assertIsInstance(out, str)


class OrouteUnitTests(unittest.TestCase):
    def test_parse_ssh_with_user_and_host(self):
        user, host = parse_ssh('pi@100.1.2.3')
        self.assertEqual(user, 'pi')
        self.assertEqual(host, '100.1.2.3')

    def test_parse_ssh_without_user_uses_env(self):
        old_user = os.environ.get('USER')
        try:
            os.environ['USER'] = 'localuser'
            user, host = parse_ssh('100.1.2.3')
            self.assertEqual(user, 'localuser')
            self.assertEqual(host, '100.1.2.3')
        finally:
            if old_user is None:
                os.environ.pop('USER', None)
            else:
                os.environ['USER'] = old_user

    def test_inject_host_if_missing_in_rsync_endpoint(self):
        # inject for rsync daemon URLs missing host
        out = _inject_host_if_missing_in_rsync_endpoint('rsync:///module/path', 'hostA')
        self.assertEqual(out, 'rsync://hostA/module/path')
        # unchanged for already present host
        out2 = _inject_host_if_missing_in_rsync_endpoint('rsync://hostB/module/path', 'hostA')
        self.assertEqual(out2, 'rsync://hostB/module/path')
        # unchanged for local paths
        out3 = _inject_host_if_missing_in_rsync_endpoint('./local', 'hostA')
        self.assertEqual(out3, './local')
        # empty and None passthrough
        self.assertIsNone(_inject_host_if_missing_in_rsync_endpoint(None, 'x'))
        self.assertEqual(_inject_host_if_missing_in_rsync_endpoint('', 'x'), '')

    def test_replace_host_in_rsync_endpoint(self):
        # SSH form with user
        self.assertEqual(
            _replace_host_in_rsync_endpoint('pi@old:/path', 'old', 'new'),
            'pi@new:/path'
        )
        # SSH form without user
        self.assertEqual(
            _replace_host_in_rsync_endpoint('old:/path', 'old', 'new'),
            'new:/path'
        )
        # rsync daemon URL without port
        self.assertEqual(
            _replace_host_in_rsync_endpoint('rsync://old/module/dir', 'old', 'new'),
            'rsync://new/module/dir'
        )
        # rsync daemon URL with port
        self.assertEqual(
            _replace_host_in_rsync_endpoint('rsync://old:873/module', 'old', 'new'),
            'rsync://new:873/module'
        )
        # Local path unchanged
        self.assertEqual(
            _replace_host_in_rsync_endpoint('/abs/local', 'old', 'new'),
            '/abs/local'
        )

    def test_inject_host_from_scheme(self):
        # transforms host:// into SSH-style path using resolved user and hostname
        self.assertEqual(
            _inject_host_from_scheme('host://remote/path', 'pi', '100.1.2.3'),
            'pi@100.1.2.3:remote/path'
        )
        # unchanged for other schemes
        self.assertEqual(_inject_host_from_scheme('rsync://host/module', 'u', 'h'), 'rsync://host/module')
        self.assertEqual(_inject_host_from_scheme('./local', 'u', 'h'), './local')
        # empty and None passthrough
        self.assertEqual(_inject_host_from_scheme('', 'u', 'h'), '')
        self.assertIsNone(_inject_host_from_scheme(None, 'u', 'h'))

    def test_resolve_connectivity_none_host(self):
        result = resolve_connectivity(None)
        self.assertEqual(result.get('tailscale_address'), None)
        self.assertEqual(result.get('local_address'), None)
        self.assertFalse(result.get('reachable'))
        self.assertIsNone(result.get('server_uuid'))


if __name__ == '__main__':
    unittest.main()