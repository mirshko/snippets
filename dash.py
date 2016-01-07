import socket
import struct
import binascii
import time
import json
import urllib2

# Use your own IFTTT key, not this fake one
ifttt_key = 'bnES2yeQT5w894e_wjj6Hj'
# Set these up at https://ifttt.com/maker
ifttt_url_coffee = 'https://maker.ifttt.com/trigger/coffee/with/key/' + ifttt_key
# Replace these fake MAC addresses and nicknames with your own
macs = {
    'a002dcf70ad2' : 'dash',
}

# Trigger a IFTTT URL. Body includes JSON with timestamp values.
def trigger_url(url):
    # data = '{ "value1" : "' + time.strftime("%Y-%m-%d") + '", "value2" : "' + time.strftime("%H:%M") + '" }'
    req = urllib2.Request(url, data, {'Content-Type': 'application/json'})
    f = urllib2.urlopen(req)
    response = f.read()
    f.close()
    return response

def coffee():
    print 'triggering coffee event, response: ' + trigger_url(ifttt_url_coffee)

rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

while True:
    packet = rawSocket.recvfrom(2048)
    ethernet_header = packet[0][0:14]
    ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header)
    # skip non-ARP packets
    ethertype = ethernet_detailed[2]
    if ethertype != '\x08\x06':
        continue
    arp_header = packet[0][14:42]
    arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)
    source_mac = binascii.hexlify(arp_detailed[5])
    source_ip = socket.inet_ntoa(arp_detailed[6])
    dest_ip = socket.inet_ntoa(arp_detailed[8])
    if source_mac in macs:
        #print "ARP from " + macs[source_mac] + " with IP " + source_ip
        if macs[source_mac] == 'dash':
            coffee()
    else:
        print "Unknown MAC " + source_mac + " from IP " + source_ip
