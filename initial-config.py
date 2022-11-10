#!/usr/bin/env python3

import binascii
import configparser
import datetime
import json
import sys
import socket
import ssl
import struct
import time
from ssl import SSLContext

import paho.mqtt.client as mqtt
import secrets

# Get Robot CA
# openssl s_client -showcerts -verify 5 -connect 192.168.10.1:8883 < /dev/null

# voodoo packet?
MAGIC_PACKET=b'\xef\xcc\x3b\x29\x00'

HOST="192.168.10.1"
PORT=8883


def hex(s: str):
    # TODO: upper, or lower?
    return s.encode('utf-8').hex().upper()


def create_msgs(config):
    ssid_f = hex(config['wifi']['ssid'])
    # Maybe some older versions need raw PSK: https://github.com/koalazak/dorita980/issues/106#issuecomment-1107924643
    psk_f = hex(config['wifi']['psk'])
    return [
        {'topic': "delta", 'qos': 1, 'payload': {"state": {"timezone": config['locale']['timezone']}}},
        # {'topic':"wifictl", 'payload':'{ "state" : { "sdiscUrl" : "https://disc-prod.iot.irobotapi.com/v1/robot/discover?robot_id=0000000000000000&country_code=FR&sku=R966040" } }'},
        # {'topic':"wifictl", 'payload':'{ "state" : { "ntphosts" : "0.irobot.pool.ntp.org 1.irobot.pool.ntp.org 2.irobot.pool.ntp.org 3.irobot.pool.ntp.org" } }'},
        # {'topic':"delta", 'payload':{ "state" : {"country" : config['locale']['country']} }},
        # {'topic':"delta", 'payload':'{ "state" : { "cloudEnv" : "prod" } }'},
        {'topic': "wifictl", 'payload': {"state": {"wlcfg": {"pass": psk_f, "sec": 7, "ssid": ssid_f}}}},
        # ssid as hex ("Test" here) https://www.rapidtables.com/convert/number/ascii-to-hex.html
        # {'topic':"wifictl", 'payload':'{ "state" : { "utctime" : 1579291795 } }'},
        # {'topic':"wifictl", 'payload':'{ "state" : { "localtimeoffset" : 60 } }'},
        {'topic': "wifictl", 'payload': { "state" : { "chkssid" : True } }},
        {'topic': "wifictl", 'payload': { "state" : { "wactivate" : True } }},
        {'topic': "wifictl", 'payload': { "state" : { "get" : "netinfo" } }},
        {'topic': "wifictl", 'payload': { "state" : { "uap" : False } }},
    ]


def redact_secrets(payload):
    def refine_dict_entry(kv):
        (key, value) = kv
        if key in ('pass', 'password', 'pwd', 'psk'):
            return key, 'REDACTED'
        else:
            return key, redact_secrets(value)

    if isinstance(payload, dict):
        return dict(map(refine_dict_entry, payload.items()))
    elif isinstance(payload, list):
        return list(map(redact_secrets, payload))
    else:
        return payload


def create_ssl_context():
    ssl_context = SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.set_ciphers('DEFAULT@SECLEVEL=1')
    ssl_context.check_hostname = False
    ssl_context.load_verify_locations('robot-ca.pem')
    ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context


def provision_password(password):
    payload=MAGIC_PACKET+password
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


def provision_wifi(password, blid, msgs):
    client = mqtt.Client(blid)

    client.tls_set_context(create_ssl_context())
    client.username_pw_set(blid, password)
    client.connect(HOST, PORT, 60)
    time.sleep(1)

    for msg in msgs:
        qos = msg.get('qos', 0)

        print('Sending:', msg['topic'], redact_secrets(msg['payload']), f"qos={qos}", flush=True)
        payload_str = msg['payload'] if isinstance(msg['payload'], str) else json.dumps(msg['payload'])
        result = client.publish(msg['topic'], payload_str, qos=qos)
        time.sleep(1)
      
    client.disconnect()
    

def create_password():
    ts = round(datetime.datetime.now().timestamp())
    rand_str = secrets.token_urlsafe(13)[:16]
    return f":1:{ts}:{rand_str}".encode("UTF-8")


def main():
    config = configparser.ConfigParser()
    config.read('config.ini')
    blid = config['roomba']['blid']
    msgs = create_msgs(config)

    cfg_password = config['roomba'].get('password')
    if cfg_password is None:
        password = create_password()
        print(f"Generated password: {password}")
    else:
        password = cfg_password

    provision_password(password)
    provision_wifi(password, blid, msgs)


if __name__ == "__main__":
    main()
