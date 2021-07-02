import Adafruit_DHT as dht
from time import sleep
from datetime import datetime
import urllib.request as urllib2
import sys

import requests

url = 'http://sggogreen.com:3000/insertData'



#apikey = "N2A72MMKR2OF0BP6"
#feedUrl = "http://sggogreen.com:3000/"

try:
    while True:
        print("\nReading Data...")
        print("At : ", datetime.now())
        humid, temp = dht.read_retry(dht.DHT11, 4)
        print("Temperature {0:0.3f} *C and Humidity {1:0.3f}". format(temp, humid))
        #conn = urllib2.urlopen(feedUrl + "&field1={0:0.3f}&field2={1:0.3f}".format(temp, humid))
        objs = {'temperature': temp, 'humidity': humid, 'deviceCode': 'RP-1002'}
        x = requests.post(url, data = objs)
        print(x.text)
        
        #print(conn.read())
        #conn.close()
        
        sleep(900)
        
except KeyboardInterrupt:
    pass