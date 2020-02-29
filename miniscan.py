import socket
import argparse
import requests
from bs4 import BeautifulSoup

### Conrad Mordzinski Week 5 (Networking) Adv. Cybersecurity Automation ###
### Professor Haley                                                     ###
print(''' 
                   _     _ _____
            ___ __|_|___|_|   __|___ ___ ___
            |     | |   | |__   |  _| .'|   |
            |_|_|_|_|_|_|_|_____|___|__,|_|_|

miniScan is a super simple port scanner. To see the help menu use -h
          ''')

def gatherArguments():
    parser = argparse.ArgumentParser()

    parser.add_argument('--host','-a', help='''set the host, or hosts addresses to 
                        be scanned. Either as IP addresses (x.x.x.x) or urls 
                        (www.example.com) separated by commas without spaces in
                        between. 
                        eg. -a 10.10.10.1,10.10.10.2 or
                        -a www.example.com,www.example2.org''')
    parser.add_argument('--port','-p', help='''set the port, or ports to be
                        scanned. Either as an individual port, or as multiple
                        ports separated by commas without spaces in between. By
                        defualt, ports 1 - 1024 are scanned.
                        eg. -p 80 or -p 80,443''') 
    parser.add_argument('--type','-t', help='''set the type of scan (TCP or
                        UDP). By default, TCP is used.
                        eg. -t tcp or -t udp''')
    parser.add_argument('--timeout','-to', help='''set the time to wait for a
                    connection to be made before moving onto the next port. By
                        default, the timeout is set to 1 second.
                        eg. -to 2 or -to 0.5''')
    args =  parser.parse_args()
    port = list(range(0,1025))
    scantype = 'TCP'
    timeout = 1
    if args.port:
        port = args.port
    if args.type:
        scantype = args.type
    if args.timeout:
        timeout = args.timeout
    if args.host:
        host = args.host
        returndict = {'host':host,'port':port,'scantype':scantype,'timeout':timeout}
        return(returndict)
    else:
        print('A valid host is required')
        pass

def miniScan(host,port,scantype,timeout):
    if scantype.upper() == 'TCP':
        hostlst = host.split(',')
        portlst = port
        try:
            portlst = port.split(',')
        except:
            pass

        for h in hostlst:
            print('\n [+] SCANNING {} USING TCP [+]'.format(h))
            for p in portlst:
                p = int(p)
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(float(timeout))
                    s.connect((h,p))
                    print('     [+] PORT {} : OPEN [+]'.format(p))
                    if p == int(80) or p == int(443):
                        try:
                            print('         [+] ATTEMPTING TO FINGERPRINT WEB SERVER [+]')
                            response = requests.get('http://'+ h)
                            headers = requests.head('http://'+ h)
                            doc = response.content
                            soup = BeautifulSoup(doc,'html.parser')
                            print('         [+] SERVER STATUS : {} [+]'.format(response.status_code))
                            print('         [+] SITE TITLE : {} [+]'.format(soup.title))
                            print('         [+] SERVER TYPE : {} [+]'.format(headers.headers['server']))
                        except:
                            pass
                except Exception as e:
                    print('     [+] PORT {} : CLOSED OR FILTERED. {}'.format(p,e))
                s.close()

    elif scantype.upper() == 'UDP':
        hostlst = host.split(',')
        portlst = port
        try:
            portlst = port.split(',')
        except:
            pass
#This is not working, and I was unable to figure out why fully. The idea is
# to send some data to the host being scanned using UDP over the port. If data
# is recieved back the port is open, if an error is recieved the port is
# unreachable. For some reason the s.recvfrom function always returns a
# recource temporarily unavaliable error, even to ports I know should be open.
        for h in hostlst:
            print('\n [+] SCANNING {} USING UDP [+]'.format(h))
            for p in portlst:
                p = int(p)
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(float(timeout))
                    s.setblocking(0)
                    data = 'OPEN?'
                    s.sendto(data.encode(),(h,p))
                    s.recvfrom(1024)
                    print('     [+] PORT {} : OPEN [+]'.format(p))
                except Exception as e:
                    print('     [+] PORT {} : CLOSED OR FILTERED. {}'.format(p,e))
                s.close()

def main():
    try:
        host = gatherArguments()['host']
        port = gatherArguments()['port']
        scantype = gatherArguments()['scantype']
        timeout = gatherArguments()['timeout']
        miniScan(host,port,scantype,timeout)
    except TypeError as e:
        pass

main()

