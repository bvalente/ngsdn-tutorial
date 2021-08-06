import json, requests, csv
from threading import Thread
from time import sleep

URL = 'http://10.0.0.1'

runs = 16
nRequests = 64
list = []
header = ["id", "run", "runId", "server"]
dataStorage = []

def sortFunc(item):
  return item['id']

def sortFunc2(item):
    return item[0]

def request(id, run, runId):
	resp = requests.get(URL)
	data = resp.json()
	list.append( {'id': id, 'run': run, 'runId': runId, 'server': data['server']} )
	global dataStorage
	dataStorage.append([id, run, runId, data['server']])
	# print(data)

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
	
	#sleep 3 second before next batch of requests
	sleep(3)


list.sort(key=sortFunc)
dataStorage.sort(key=sortFunc2)
out = {}
out['list'] = list
with open('/tmp/data.json', 'w') as outfile:
    json.dump(out, outfile)
with open('/tmp/data.csv', 'w') as f:
    write = csv.writer(f) 
    write.writerow(header)
    write.writerows(dataStorage)

#TODO maybe delete json implementation, including 'list' object