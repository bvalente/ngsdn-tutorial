

#http request servers
#gather info
#plot chart

#16 requests in paralel

import json, requests
from threading import Thread
from time import sleep

URL = 'http://10.0.0.1'

list = []

def sortFunc(item):
  return item['id']

def request(id):
	resp = requests.get(URL)
	data = resp.json()
	list.append( {'id': id, 'server': data['server']} )
	# print(data)

index = 1
for i in range(0,4):

	#create 16 request threads
	threads = []
	for j in range(0,16):
		t = Thread(target=request, args=(index,))
		index += 1
		threads.append(t)
		t.start()
	
	#wait for all threads
	for t in threads:
		t.join()
	
	#sleep 1 second before next batch of requests
	sleep(1)


list.sort(key=sortFunc)
# print(list)
out = {}
out['list'] = list
with open('/tmp/data.json', 'w') as outfile:
    json.dump(out, outfile)
