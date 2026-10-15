"""Mock Desktop/process readiness; never stops the user's Docker engine."""
import subprocess
import os
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from launcher.docker_setup import ensure_docker_linux, linux_engine_ready, launch_desktop


class DockerSetupTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows startup flags")
    def test_desktop_launch_is_hidden_and_detached(self) -> None:
        with patch("launcher.docker_setup.subprocess.Popen") as process:
            launch_desktop(Path("Desktop.exe"))
            args, options = process.call_args
            self.assertEqual(args[0], ["Desktop.exe"])
            self.assertEqual(options["startupinfo"].wShowWindow, subprocess.SW_HIDE)
            self.assertTrue(options["creationflags"] & subprocess.DETACHED_PROCESS)
            self.assertEqual(options["stdout"], subprocess.DEVNULL)

    def test_running_linux_engine_does_not_launch_desktop(self) -> None:
        with patch("launcher.docker_setup.docker_executable", return_value="docker.exe"), \
             patch("launcher.docker_setup.linux_engine_ready", return_value=True), \
             patch("launcher.docker_setup.launch_desktop") as launch:
            self.assertEqual(ensure_docker_linux(), "docker.exe")
            launch.assert_not_called()

    def test_stopped_desktop_launched_once_and_waits_for_readiness(self) -> None:
        with patch("launcher.docker_setup.sys.platform", "win32"), \
             patch("launcher.docker_setup.docker_executable", return_value="docker.exe"), \
             patch("launcher.docker_setup.desktop_executable", return_value=Path("Desktop.exe")), \
             patch("launcher.docker_setup.linux_engine_ready", side_effect=[False, False, True]), \
             patch("launcher.docker_setup.launch_desktop") as launch:
            messages = []
            self.assertEqual(ensure_docker_linux(report=messages.append), "docker.exe")
            launch.assert_called_once()
            self.assertIn("sẵn sàng", messages[-1])

    def test_windows_containers_are_not_silently_switched(self) -> None:
        result = subprocess.CompletedProcess([], 0, stdout="windows\n", stderr="")
        with patch("launcher.docker_setup.subprocess.run", return_value=result), \
             patch("launcher.docker_setup.docker_executable", return_value="docker.exe"), \
             patch("launcher.docker_setup.launch_desktop") as launch:
            with self.assertRaisesRegex(RuntimeError, "Windows containers"):
                ensure_docker_linux()
            launch.assert_not_called()

    def test_timeout_is_bounded_and_explains_wsl_setup(self) -> None:
        with patch("launcher.docker_setup.sys.platform", "win32"), \
             patch("launcher.docker_setup.docker_executable", return_value="docker.exe"), \
             patch("launcher.docker_setup.desktop_executable", return_value=Path("Desktop.exe")), \
             patch("launcher.docker_setup.linux_engine_ready", return_value=False), \
             patch("launcher.docker_setup.launch_desktop"), \
             patch("launcher.docker_setup.time.monotonic", side_effect=[0, 0, 2, 2]):
            with self.assertRaisesRegex(RuntimeError, "WSL2"):
                ensure_docker_linux(timeout_sec=1)

    def test_cancelled_before_launch_does_not_start_desktop(self) -> None:
        cancel = threading.Event()
        cancel.set()
        with patch("launcher.docker_setup.docker_executable", return_value="docker.exe"), \
             patch("launcher.docker_setup.launch_desktop") as launch:
            with self.assertRaises(InterruptedError):
                ensure_docker_linux(cancel=cancel)
            launch.assert_not_called()

    def test_missing_desktop_is_actionable(self) -> None:
        with patch("launcher.docker_setup.sys.platform", "win32"), \
             patch("launcher.docker_setup.docker_executable", return_value="docker.exe"), \
             patch("launcher.docker_setup.linux_engine_ready", return_value=False), \
             patch("launcher.docker_setup.desktop_executable", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "executable not found"):
                ensure_docker_linux()

    def test_failed_or_timed_out_probe_is_not_ready(self) -> None:
        for response in (subprocess.CompletedProcess([], 1, stdout="", stderr="unavailable"), subprocess.TimeoutExpired("docker", 3)):
            with patch("launcher.docker_setup.subprocess.run", **({"side_effect": response} if isinstance(response, Exception) else {"return_value": response})):
                self.assertFalse(linux_engine_ready("docker.exe", 3))


if __name__ == "__main__":
    unittest.main()
