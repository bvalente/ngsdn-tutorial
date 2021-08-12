import json, requests, csv, datetime
from threading import Thread
from time import sleep

URL = 'http://10.0.0.1'

runs = 16
nRequests = 64
SLEEP = 1.5
header = ["id", "run", "runId", "server", "elapsed"]
dataStorage = []

def sortFunc(item):
    return item[0]

def request(id, run, runId):
	resp = requests.get(URL)
	data = resp.json()
	global dataStorage
	dataStorage.append([id, run, runId, data['server'], resp.elapsed])

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
	
	#wait for all threads
	for t in threads:
		t.join()
	
	#sleep x second before next batch of requests
	sleep(SLEEP)


dataStorage.sort(key=sortFunc)
csvFile = '/tmp/data_{}.csv'.format( datetime.datetime.now().strftime('%Y%m%d%H%M%S') )
with open(csvFile, 'w') as f:
    write = csv.writer(f) 
    write.writerow(header)
    write.writerows(dataStorage)