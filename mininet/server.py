#!/usr/bin/env python2

import os, sys, subprocess, socket, time, threading, random, json, argparse, signal
import SimpleHTTPServer
import SocketServer
import logging

CONTROLLER_IP = "10.0.0.254"
CONTROLLER_MAC = "00:aa:00:00:00:ff"
PORT = 80

timerListGlobal = []

def sendCpuLoadLoop(args, alive, opened_socket):
    while alive[0]:
        time.sleep(1)
        cmd = 'top -bcn2 -w512 | grep -v grep | grep python | grep %s | tail -1 | awk \'{print $9}\'' % args.serverName
        cpu = subprocess.check_output(cmd, shell=True)
        message = args.serverName + ":cpu:" + str(cpu).split('\n')[0]
        byte_message = message.encode("utf-8")
        try:
            opened_socket.sendto(byte_message, (CONTROLLER_IP, 5005))
        except:
            pass

def sendCpuLoad(args, alive):
    opened_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    thread = threading.Thread(target=sendCpuLoadLoop, args=(args, alive, opened_socket))
    thread.start()
    return (opened_socket, thread)

def cpuLoad(load):
    for i in range(0, load):
        x = random.random()
        x * x ** x

#TODO should also send max value?
# receive list with time taken to process each GET and calculate the average
def sendTimerList(serverName, timerList):
    logging.debug("Sending timer to controller")
    opened_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    message = serverName + ":timer:" + str(sum(timerList) / len(timerList))
    byte_message = message.encode("utf-8")
    try:
        opened_socket.sendto(byte_message, (CONTROLLER_IP, 5005))
    except:
        pass
    finally:
        opened_socket.close()

def MakeGetHandler(args):
    
    class GetHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):

        def __init__(self, request, client_address, server):
            self.serverName = args.serverName
            SimpleHTTPServer.SimpleHTTPRequestHandler.__init__(self, request, client_address, server)
            logging.debug("Handler Started")

        def log_message(self, format, *args):
            pass

        def _set_headers(self):
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
        
        def handle_one_request(self):
            start = time.time()
            logging.debug("Request received")
            SimpleHTTPServer.SimpleHTTPRequestHandler.handle_one_request(self)
            end = time.time() - start
            logging.debug("Request took %s sec" % end)

            global timerListGlobal
            timerListGlobal += [end]
            logging.debug("Timer List: %s" % ', '.join(map(str, timerListGlobal)) )

            if (len(timerListGlobal) >= 10):
                sendTimerList(self.serverName, timerListGlobal)
                timerListGlobal = []

        def do_HEAD(self):
            self._set_headers()

        def do_GET(self):
            self._set_headers()
            self.wfile.write(json.dumps({'server': self.serverName}))

            if (self.serverName == "server2"):
                cpuLoad(1000)
    
    return GetHandler

def main():

    #argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument('serverName', type=str, help="Server id")
    args = parser.parse_args()

    #logging
    filename = "/tmp/%s.out" % args.serverName
    logging.basicConfig(filename=filename, encoding='utf-8', level=logging.DEBUG)
    logging.info("Server %s Started" % args.serverName)

    #http server
    HandlerClass = MakeGetHandler(args)
    httpd = SocketServer.TCPServer(("", PORT), HandlerClass)

    #inject controller in ARP Table
    os.system('arp -s %s %s' % (CONTROLLER_IP, CONTROLLER_MAC))

    #thread to send cpu load
    cpuLoadAlive = [True] #pass variable as reference
    (cpuLoadSocket, cpuLoadThread) = sendCpuLoad(args, cpuLoadAlive)

    #SIGINT
    def signal_handler(sig, frame):
        logging.info("Signal handler, shutdown server")

        logging.debug("Closing cpuLoad socket")
        cpuLoadAlive[0] = False
        cpuLoadThread.join()
        cpuLoadSocket.close()

        logging.debug("Shutdown httpd")
        threading.Thread(target=httpd.shutdown).start()

        logging.debug("Exiting Signal handler")
    
    signal.signal(signal.SIGINT, signal_handler)

    #start http server
    httpd.serve_forever()

    logging.info("Exit")

if __name__ == "__main__":
    main()