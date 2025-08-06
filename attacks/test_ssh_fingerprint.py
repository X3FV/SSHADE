import unittest
from attacks.ssh_fingerprint import SSHFingerprint

class TestSSHFingerprint(unittest.TestCase):
    def test_parse_banner_typical(self):
        banner = "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3"
        fp = SSHFingerprint("dummy")
        result = fp.parse_banner(banner)
        self.assertEqual(result['software'], "OpenSSH")
        self.assertEqual(result['version'], "7.6p1")
        self.assertEqual(result['os'], "Ubuntu-4ubuntu0.3")

    def test_parse_banner_no_os(self):
        banner = "SSH-2.0-OpenSSH_8.0"
        fp = SSHFingerprint("dummy")
        result = fp.parse_banner(banner)
        self.assertEqual(result['software'], "OpenSSH")
        self.assertEqual(result['version'], "8.0")
        self.assertIsNone(result['os'])

    def test_parse_banner_empty(self):
        fp = SSHFingerprint("dummy")
        result = fp.parse_banner("")
        self.assertIsNone(result['software'])
        self.assertIsNone(result['version'])
        self.assertIsNone(result['os'])

    def test_parse_banner_malformed(self):
        banner = "SSH-2.0-UnknownBanner"
        fp = SSHFingerprint("dummy")
        result = fp.parse_banner(banner)
        # In this case, software should be "UnknownBanner" and version/os None
        self.assertEqual(result['software'], "UnknownBanner")
        self.assertIsNone(result['version'])
        self.assertIsNone(result['os'])

    def test_grab_banner_connection_error(self):
        # Use an invalid IP to simulate connection error
        fp = SSHFingerprint("10.255.255.1", timeout=1)
        banner = fp.grab_banner()
        self.assertIsNone(banner)

    # Note: The following test requires an actual SSH server running on localhost port 22
    # Uncomment to run if such a server is available
    # def test_grab_banner_success(self):
    #     fp = SSHFingerprint("127.0.0.1", timeout=2)
    #     banner = fp.grab_banner()
    #     self.assertIsNotNone(banner)
    #     self.assertTrue(banner.startswith("SSH-"))

if __name__ == "__main__":
    unittest.main()
