#!/usr/bin/env python3

import sys
from scapy.all import *

sniffed_count = 0

def countPackets(pkt):
  global sniffed_count
  sniffed_count += 1
  print('{} sniffed so far     '.format(sniffed_count), end='\r')

def printUsage():
  print("Usage: cap.py <iface> [output.cap]")

def main():
    try:
      argc = len(sys.argv)

      if(argc < 2 or argc > 3):
        printUsage()
        sys.exit(1)
      else:
        sniff_iface = sys.argv[1]
        outname = "output.cap"
        packet_count = 10000
        if(argc == 3):
          outname = sys.argv[2]

        print("Sniffing {} packets from {}...".format(packet_count, sniff_iface))
        packets = sniff(prn=countPackets, iface=sniff_iface, count=packet_count)
        print("Storing packets to {}...".format(outname))
        wrpcap(outname, packets)
        print("Done!")

    except OSError:
      print("Couldn't sniff; are you sure that iface exists?")
      sys.exit(2)

    except PermissionError:
      print("Insufficient permissions! Are you running as root?")
      sys.exit(3)

    except KeyboardInterrupt:
      print("Canceling...")
      pass
    sys.exit(0)


if __name__ == "__main__":
    main()