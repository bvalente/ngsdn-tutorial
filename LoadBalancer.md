
'''
h1 ab -k -n 50000 -c 100 -t 20 http://10.0.0.1/
h1 ab -n 2048 -c 16 http://10.0.0.1/
h1 /mininet/my-curl.sh
h1 httperf --hog --server 10.0.0.1 --rate 64 --num-conn 3840
'''