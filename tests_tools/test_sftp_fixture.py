import unittest

from tests_runtime.lab.sftp_receiver import HOST_LINK, PEER_LINK


class SftpFixtureTests(unittest.TestCase):
    def test_veth_names_fit_linux_interface_limit_and_are_distinct(self):
        self.assertNotEqual(HOST_LINK, PEER_LINK)
        for name in (HOST_LINK, PEER_LINK):
            self.assertLessEqual(len(name.encode("ascii")), 15)
