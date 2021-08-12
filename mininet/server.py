#!/usr/bin/env python2

import os, sys, subprocess, socket, time, threading, random, json, argparse, signal
import SimpleHTTPServer
import SocketServer
import logging

CONTROLLER_IP = "10.0.0.254"
CONTROLLER_MAC = "00:aa:00:00:00:ff"
PORT = 80
CPU=False
LATENCY=True

latencyListGlobal = []

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
def sendLatencyList(serverName, latencyList):
    logging.debug("Sending latency to controller")
    opened_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #format: serverX:latency:<avg latency>:<sum latency>
    message = serverName + ":latency:" + str(sum(latencyList) / len(latencyList)) + ":" + str(sum(latencyList))
    byte_message = message.encode("utf-8")
    try:
        opened_socket.sendto(byte_message, (CONTROLLER_IP, 5005))
    except:
        pass
    finally:
        opened_socket.close()

def sendLatencyLoop(args, alive, mySocket):
    global latencyListGlobal
    while alive[0]:
        time.sleep(3)
        if (len(latencyListGlobal) > 0):
            #format: serverName:latency:<avg latency>:<sum latency>
            message = args.serverName + ":latency:" + str(sum(latencyListGlobal) / len(latencyListGlobal)) + ":" + str(sum(latencyListGlobal)) + ":" + str(max(latencyListGlobal))
            byte_message = message.encode("utf-8")
            try:
                mySocket.sendto(byte_message, (CONTROLLER_IP, 5005))
                latencyListGlobal = [] #reset list
            except:
                pass

def sendLatency(args, alive):
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    thread = threading.Thread(target=sendLatencyLoop, args=(args, alive, mySocket))
    thread.start()
    return (mySocket, thread)

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

            if(LATENCY):
                global latencyListGlobal
                latencyListGlobal += [end]
                logging.debug("Latency List: %s" % ', '.join(map(str, latencyListGlobal)) )

                if (len(latencyListGlobal) >= 10 and False): #disable send list here
                    sendlatencyList(self.serverName, latencyListGlobal)
                    latencyListGlobal = []

        def do_HEAD(self):
            self._set_headers()

        def do_GET(self):
            self._set_headers()
            self.wfile.write(json.dumps({'server': self.serverName}))

            #artificial load/l  atency
            if (self.serverName == "server1"):
                logging.debug("sleeping 0.07")
                time.sleep(0.07)
            elif (self.serverName == "server2"):
                # cpuLoad(1000)
                logging.debug("sleeping 0.1")
                time.sleep(0.1) # alternative for artificial latency
    
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
    if (CPU):
        cpuLoadAlive = [True] #pass variable by reference
        (cpuLoadSocket, cpuLoadThread) = sendCpuLoad(args, cpuLoadAlive)
    
    if(LATENCY):
        latencyAlive = [True] #pass variable by reference
        (latencySocket, latencyThread) = sendLatency(args, latencyAlive)

    #SIGINT
    def signal_handler(sig, frame):
        logging.info("Signal handler, shutdown server")

        if (CPU):
            logging.debug("Closing cpuLoad socket")
            cpuLoadAlive[0] = False
            cpuLoadThread.join()
            cpuLoadSocket.close()
        
        if (LATENCY):
            logging.debug("Closing latency socket")
            latencyAlive[0] = False
            latencyThread.join()
            latencySocket.close()

        logging.debug("Shutdown httpd")
        threading.Thread(target=httpd.shutdown).start()

        logging.debug("Exiting Signal handler")
    
    signal.signal(signal.SIGINT, signal_handler)

    #start http server
    httpd.serve_forever()

    logging.info("Exit")

if __name__ == "__main__":
    main()