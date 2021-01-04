from modules import crafter
import unittest
from scapy.all import *
import socket
from modules import tcping
from modules.structures import *
from scapy.all import *


class TestTCPing(unittest.TestCase):
    def test_