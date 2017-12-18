#!/usr/bin/python3
import binascii
import unittest
import segwit_addr
import sys


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print('usage: %s [ln addr]' % sys.argv[0])
        quit()
    nodeid = segwit_addr.lnnode_decode(sys.argv[1])
    if nodeid is None:
        print('fail decode')
        quit()
    for bt in nodeid:
        print(format(bt, '02x'), end='')
    print('')
