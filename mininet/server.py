#!/usr/bin/env python2

import os, sys, subprocess, socket, time, threading, random
import SimpleHTTPServer
import SocketServer
import logging

CONTROLLER_IP = "10.0.0.254"
CONTROLLER_MAC = "00:aa:00:00:00:ff"
PORT = 80

def sendCpuLoad ():
    opened_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        time.sleep(1)
        cmd = 'top -bcn2 -w512 | grep -v grep | grep python | grep %s | tail -1 | awk \'{print $9}\'' % sys.argv[1]
        cpu = subprocess.check_output(cmd, shell=True)
        message = sys.argv[1] + ":" + str(cpu).split('\n')[0]
        byte_message = message.encode("utf-8")
        opened_socket.sendto(byte_message, (CONTROLLER_IP, 5005))
        # print('message sent: %s' % message)

def cpuLoad( load):
    for i in range(0, load):
        x = random.random()
        x * x ** x

class GetHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):

    def log_message(self, format, *args):
        pass

    def do_GET(self):

        SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)

        cpuLoad(1000)

# print('INIT')

logging.basicConfig(level=logging.INFO)
Handler = GetHandler
httpd = SocketServer.TCPServer(("", PORT), Handler)

os.system('arp -s %s %s' % (CONTROLLER_IP, CONTROLLER_MAC))
threading.Thread(target=sendCpuLoad).start()

httpd.serve_forever()
