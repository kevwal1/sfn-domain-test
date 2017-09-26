import datetime
import time
import requests
#Create By - Michael Clark
TIMES = 1

utcnow = datetime.datetime.utcnow()

def getAllDomains(FILE_NAME):
    allDomains =[]
    domainFile = open(FILE_NAME)
    for line in domainFile:
        line = line.strip()
        allDomains.append(line)
    return allDomains


def makeARequest(threatContent):
    url = 'http://127.0.0.1:8807/CreateRecord'
    payload = '{"Domain":"1","Receive Time":"2017-09-03 07:24:00","Serial #":"001606029093","Type":"THREAT","Threat/Content Type":"vulnerability",' \
              '"Config Version":"1","Generate Time":"2017/04/25 15:23:21","Source address":"213.211.198.62","Destination address":"10.0.1.27",' \
              '"NAT Source IP":"213.211.198.62","NAT Destination IP":"69.246.218.42","Rule":"Positive Security","Source User":"",' \
              '"Destination User":"","Application":"web-browsing","Virtual System":"vsys_name","Source Zone":"Internal","Destination Zone":"Internet",' \
              '"Inbound Interface":"ethernet1/1","Outbound Interface":"ethernet1/3","Log Action":"SNapi-forwarding","Time Logged":"2017/04/25 15:23:21",' \
              '"Session ID":"","Repeat Count":"3","Source Port":"59447","Destination Port":"80","NAT Source Port":"17518","NAT Destination Port":"80",' \
              '"Flags":"53335","IP Protocol":"tcp","Action":"alert","URL":"eicar.com","Threat/Content Name":"'+threatContent+'","Category":"",' \
              '"Severity":"medium","Direction":"server-to-client","seqno":"","actionflags":"","Source Country":"Germany","Destination Country":"10.0.0.0-10.255.255.255",' \
              '"cpadding":"","contenttype":"","pcap_id":"","filedigest":"","cloud":"","url_idx":"","user_agent":"","filetype":"","xff":"","referer":"","sender":"","subject":"","recipient":"","reportid":"0","dg_hier_level_1":"0","dg_hier_level_2":"0","dg_hier_level_3":"0","dg_hier_level_4":"","vsys_name":"","device_nam":"PA-200","file_url":"","Source VM UUID":"","Destination VM UUID":"","http_method":"","Tunnel ID/IMSI":"","Monitor Tag/IMEI":"",' \
              '"Parent Session ID":"","parent_start_time":"","tunnel":"N/A","thr_category":"code-execution","contentver":"AppThreat-690-3977","sig_flags":"0x0"}'

    headers = {'Content-Type': 'application/json'}
    r = requests.post(url, data=payload, headers=headers)
    print (r.text)    
def main():
    allDomains = getAllDomains("Domain.txt")
    
    for d in allDomains:
        makeARequest(d)
        print (d)
if __name__ == '__main__':
    main()
