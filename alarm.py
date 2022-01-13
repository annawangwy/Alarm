#!/usr/bin/python3

import argparse
import base64

from scapy.all import *

count = 0
username = ' '
password = ' '

def packetcallback(packet):
  global count
  global username
  global password
  try:
    # NULL scan
    if packet.haslayer(TCP) and packet[TCP].flags == 0:
        count += 1
        print("ALERT #" + str(count) + ": NULL scan is detected from " + str(packet[IP].src) +
              " (TCP) " + "source port: " + str(packet[TCP].sport) +
              " destination port: " + str(packet[TCP].dport) + " !" )

    # # FIN scan
    if packet.haslayer(TCP) and packet[TCP].flags == 1:
        count += 1
        print("ALERT #" + str(count) + ": FIN scan is detected from " + str(packet[IP].src) +
            " (TCP) " + "source port: " + str(packet[TCP].sport) +
            " destination port: " + str(packet[TCP].dport) + " !" )

    # # Xmas scan
    if packet.haslayer(TCP) and packet[TCP].flags == 41:
        count += 1
        print("ALERT #" + str(count) + ": Xmas scan is detected from " + str(packet[IP].src) +
            " (TCP) " + "source port: " + str(packet[TCP].sport) +
            " destination port: " + str(packet[TCP].dport) + " !" )

    # Nikto scan
    if "Nikto" in str(packet[Raw].load):
        count += 1
        print("ALERT #" + str(count) + ": Nikto scan is detected from " + str(packet[IP].src) +
            " (HTTP) " + "source port: " + str(packet[TCP].sport) +
            " destination port: " + str(packet[TCP].dport) + " !" )

    # SMB protocol
    if packet.haslayer(TCP) and packet[TCP].dport == 139 or packet[TCP].dport == 445 or \
            packet[TCP].sport == 139 or packet[TCP].sport == 445:
        count += 1
        print("ALERT #" + str(count) + ": SMB scan is detected from " + str(packet[IP].src) +
              " (SMB) " + "source port: " + str(packet[TCP].sport) +
              " destination port: " + str(packet[TCP].dport) + " !")

    # password info: scanning for FTP protocol
    if packet.haslayer(TCP) and packet[TCP].dport == 21:
        if "USER" in packet[TCP].load.decode("ascii"):
          username = str(packet[TCP].load.decode("ascii"))
          username = username.lstrip("USER ")
        if "PASS" in packet[TCP].load.decode("ascii"):
          count += 1
          password = str(packet[TCP].load.decode("ascii"))
          password = password.lstrip("PASS ")
          print("ALERT #" + str(count) + " Usernames and passwords sent in-the-clear ( FTP ) " +
              " {username: " + username + ", password: " + password + "}")

    # password info: scanning for HTTP protocol
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        if 'Authorization: Basic' in packet[TCP].load.decode("ascii"):
          for line in packet[TCP].load.decode("ascii").splitlines():
            if 'Authorization: Basic' in line:
              credentials = line.strip('Authorization: Basic')
              credentials = base64.b64decode(credentials)
              cred_str = str(credentials)
              cred_str = cred_str.lstrip("b'")
              cred_str = cred_str.rstrip("'")
              cred_str = cred_str.split(":")
              count += 1
              print("ALERT #" + str(count) + " Usernames and passwords sent in-the-clear (HTTP) " +
                     "{username: " + cred_str[0] + ", password: " + cred_str[1] + "}")

    # password info: scanning for IMAP protocol
    if packet.haslayer(TCP) and packet[TCP].dport == 993 or packet[TCP].dport == 143:
        if "LOGIN" in packet[TCP].load.decode("ascii"):
          imap_p = str(packet[TCP].load.decode("ascii"))
          imap_p = imap_p.lstrip("3 LOGIN ")
          imap_p = imap_p.split(" ")
          imap_p[1] = imap_p[1].lstrip('"')
          imap_p[1] = imap_p[1].rstrip('"')
          count += 1
          print("ALERT #" + str(count) + " Usernames and passwords sent in-the-clear (IMAP) " +
          "{username: " + imap_p[0] + ", password: " + imap_p[1] + "}")

  except:
      pass

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")