import json, requests, csv, datetime, time
from threading import Thread
from time import sleep

URL = 'http://10.0.0.1'

runs = 32
nRequests = 128
miniSLEEP = 0.08
SLEEP = 15
header = ["id", "run", "runId", "server", "elapsed"]
dataStorage = []

def sortFunc(item):
    return item[0]

def request(id, run, runId):
	global dataStorage
	start = time.time()
	try:
		resp = requests.get(URL)
		end = time.time() - start
		data = resp.json()
		dataStorage.append([id, run, runId, data['server'], end])
	except: 
		print("Exception on GET!")

	# print(end)

index = 1
for i in range(0, runs):

	print("sending run %s, requests %s - %s" % (i, str(i*nRequests), str((i+1)*nRequests-1)) )
	#create n request threads
	threads = []
	for j in range(0, nRequests):
		t = Thread(target=request, args=(index, i, j))
		index += 1
		threads.append(t)
		t.start()
		sleep(miniSLEEP) #less stress on the servers
	
	#wait for all threads
	for t in threads:
		t.join()
	
	#sleep x second before next batch of requests
	print("sleeping for %s seconds" % SLEEP)
	sleep(SLEEP)

	#waiting for user input
	# enter = raw_input("Waiting for input")


dataStorage.sort(key=sortFunc)
csvFile = '/tmp/data_{}.csv'.format( datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S') )
with open(csvFile, 'w') as f:
    write = csv.writer(f) 
    write.writerow(header)
    write.writerows(dataStorage)