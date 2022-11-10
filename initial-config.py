#!/usr/bin/env python3

import binascii
import sys
import socket
import ssl
import struct
import time
from ssl import SSLContext

import paho.mqtt.client as mqtt

# Get Robot CA
# openssl s_client -showcerts -verify 5 -connect 192.168.10.1:8883 < /dev/null

msgs = [
    {'topic':"delta", 'payload':'{ "state" : { "timezone" : "Europe/Paris" } }'},
    #{'topic':"wifictl", 'payload':'{ "state" : { "sdiscUrl" : "https://disc-prod.iot.irobotapi.com/v1/robot/discover?robot_id=0000000000000000&country_code=FR&sku=R966040" } }'},
    #{'topic':"wifictl", 'payload':'{ "state" : { "ntphosts" : "0.irobot.pool.ntp.org 1.irobot.pool.ntp.org 2.irobot.pool.ntp.org 3.irobot.pool.ntp.org" } }'},
    #{'topic':"delta", 'payload':'{ "state" : {"country" : "FR"} }'},
    #{'topic':"delta", 'payload':'{ "state" : { "cloudEnv" : "prod" } }'},
    {'topic':"wifictl", 'payload':'{"state": {"wlcfg": {"pass": "wifisecretpasssword", "sec": 7, "ssid": "54657374"}}}'},  # ssid as hex ("Test" here) https://www.rapidtables.com/convert/number/ascii-to-hex.html
    #{'topic':"wifictl", 'payload':'{ "state" : { "utctime" : 1579291795 } }'},
    #{'topic':"wifictl", 'payload':'{ "state" : { "localtimeoffset" : 60 } }'},
    {'topic':"wifictl", 'payload':'{ "state" : { "chkssid" : true } }'},
    {'topic':"wifictl", 'payload':'{ "state" : { "wactivate" : true } }'},
    {'topic':"wifictl", 'payload':'{ "state" : { "get" : "netinfo" } }'},
    {'topic':"wifictl", 'payload':'{ "state" : { "uap" : false } }'},
]

# voodoo packet?
MAGIC_PACKET=b'\xef\xcc\x3b\x29\x00'

# Your BLID: Check the wifi AP name
BLID='80A7001234567890'

# format:  :1:timestamp:16 alpha-decimal chars
PASSWORD=b':1:1579195386:8fx7nYqVtKgWJ9tO'

HOST="192.168.10.1"
PORT=8883


def create_ssl_context():
    ssl_context = SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.set_ciphers('DEFAULT@SECLEVEL=1')
    ssl_context.check_hostname = False
    ssl_context.load_verify_locations('robot-ca.pem')
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context


def provision_password():
    payload=MAGIC_PACKET+PASSWORD
    authentication_exchange=b'\xf0'+bytes([len(payload)])+payload

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    ssl_context = create_ssl_context()
    wrappedSocket = ssl_context.wrap_socket(sock)

    try:
        wrappedSocket.connect((HOST, PORT))
    except Exception as e:
        print("Connection Error %s" % e)

    wrappedSocket.send(authentication_exchange)

    data = b''
    data_len = len(payload)
    while True:
        try:
            # NOTE data is 0xf0 (mqtt RESERVED) length (0x23 = 35),
            # 0xefcc3b2900 (magic packet), 0xXXXX... (30 bytes of
            # password). so 7 bytes, followed by 30 bytes of password
            # (total of 37)
            if len(data) >= data_len+2:
                break
            data_received = wrappedSocket.recv(1024)
            print("received data: hex: %s, length: %d" % (binascii.hexlify(data_received), len(data_received)), flush=True)
        except socket.error as e:
            print("Socket Error: %s" % e)
            break

        if len(data_received) == 0:
            print("socket closed")
            break
        else:
            data += data_received
            if len(data) >= 2:
                data_len = struct.unpack("B", data[1:2])[0]

    wrappedSocket.close()
    print("received data: hex: %s, length: %d" % (binascii.hexlify(data), len(data)))

    if len(data) <= 7:
        print('Error setting password, receive %d bytes. Follow the '
              'instructions and try again.' % len(data))
        sys.exit(1)
    time.sleep(2)


def provision_wifi():
    client = mqtt.Client(BLID)
    client.tls_set_context(create_ssl_context())
    client.username_pw_set(BLID, PASSWORD)
    client.connect("192.168.10.1", 8883, 60)

    time.sleep(1)
    for msg in msgs:
        print('Sending:', msg['topic'], msg['payload'], flush=True)
        client.publish(msg['topic'], msg['payload'])
        time.sleep(1)
      
    client.disconnect()
    


def main():
    provision_password()
    provision_wifi()

if __name__ == "__main__":
    main()
