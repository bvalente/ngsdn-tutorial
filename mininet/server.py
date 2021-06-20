#!/usr/bin/env python2

import sys, threading, random
import SimpleHTTPServer
import SocketServer
import logging

PORT = 80

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
            

logging.basicConfig(level=logging.INFO)
print('hello')
Handler = GetHandler
httpd = SocketServer.TCPServer(("", PORT), Handler)

httpd.serve_forever()

#TODO add apache-utils to image