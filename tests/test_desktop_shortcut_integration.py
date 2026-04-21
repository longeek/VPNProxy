import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(sys.platform == "win32", "Desktop shortcut integration is Windows-only")
class DesktopShortcutIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.project_root = Path(__file__).resolve().parents[1]
        self.script = self.project_root / "scripts" / "create_desktop_shortcut.ps1"
        self.python = shutil.which("python")
        if not self.python:
            self.skipTest("python not on PATH")

    def test_shortcut_target_args_workdir(self):
        tmp_desktop = Path(tempfile.mkdtemp(prefix="vpnproxy_desktop_"))
        self.addCleanup(lambda: shutil.rmtree(tmp_desktop, ignore_errors=True))
        token = "integration_test_token_only"

        create = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(self.script),
            "-ProjectRoot",
            str(self.project_root),
            "-PythonExe",
            self.python,
            "-Token",
            token,
            "-Server",
            "127.0.0.1",
            "-ServerPort",
            "8443",
            "-DesktopPath",
            str(tmp_desktop),
            "-LinkName",
            "VPNProxyClientTest.lnk",
        ]
        r = subprocess.run(create, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

        lnk = tmp_desktop / "VPNProxyClientTest.lnk"
        self.assertTrue(lnk.is_file(), "shortcut file missing")

        read_ps = (
            '$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:VPNPROXY_TEST_LNK);'
            "Write-Output ('TARGET=' + $s.TargetPath);"
            "Write-Output ('ARGS=' + $s.Arguments);"
            "Write-Output ('WORKDIR=' + $s.WorkingDirectory)"
        )
        env = {**os.environ, "VPNPROXY_TEST_LNK": str(lnk.resolve())}

        r2 = subprocess.run(
            ["powershell", "-NoProfile", "-Command", read_ps],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )
        self.assertEqual(r2.returncode, 0, r2.stderr)
        lines = {line.split("=", 1)[0]: line.split("=", 1)[1] for line in r2.stdout.strip().splitlines() if "=" in line}

        self.assertEqual(
            os.path.normcase(lines["TARGET"].strip()),
            os.path.normcase(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "system32", "cmd.exe")),
        )
        self.assertIn("start_vpn_proxy.cmd", lines["ARGS"])
        self.assertEqual(
            Path(lines["WORKDIR"].strip()).resolve(),
            self.project_root.resolve(),
        )

        cmd_file = self.project_root / "start_vpn_proxy.cmd"
        self.assertTrue(cmd_file.is_file(), "cmd launcher file missing")
        cmd_content = cmd_file.read_text(encoding="utf-8", errors="replace")
        self.assertIn("client.py", cmd_content)
        self.assertIn(token, cmd_content)
        self.assertIn("--http-port 8080", cmd_content)


if __name__ == "__main__":
    unittest.main()
