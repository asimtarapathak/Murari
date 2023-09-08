import email
from email.header import decode_header
from email import policy
from http.client import SERVICE_UNAVAILABLE
import optparse
import re,sys
from colorama import Fore, Back, Style
from ip2geotools.databases.noncommercial import DbIpCity 
from prettytable import PrettyTable
from tabulate import tabulate
import virustotal_python
from virustotal_python import Virustotal
from pprint import pprint
from base64 import urlsafe_b64encode
import hashlib
from extract_msg import Message
import extract_msg
import requests

api_key = "<Enter your VirusTotal API key>"

def ip_lookup(ip_addr):
    response = DbIpCity.get(ip_addr, api_key='free')

    # assign data
    mydata = [
        [Back.RED+"[+] IP Address "+Style.RESET_ALL,Fore.GREEN+response.ip_address+Style.RESET_ALL],
        [Back.RED+"[+] Country "+Style.RESET_ALL,Fore.GREEN+response.country+Style.RESET_ALL],
        [Back.RED+"[+] City "+Style.RESET_ALL,Fore.GREEN+response.city+Style.RESET_ALL],
        [Back.RED+"[+] Region "+Style.RESET_ALL,Fore.GREEN+response.region+Style.RESET_ALL],
        [Back.RED+"[+] Latitude "+Style.RESET_ALL,Fore.GREEN+str(response.latitude)+Style.RESET_ALL],
        [Back.RED+"[+] Longitude "+Style.RESET_ALL,Fore.GREEN+str(response.longitude)+Style.RESET_ALL]
    ]
    
    # create header
    head = [Back.LIGHTBLUE_EX+"Title"+Style.RESET_ALL, Back.LIGHTBLUE_EX+"Response"+Style.RESET_ALL]
    
    print(Fore.BLACK+Back.BLUE+"[######] IP LookUP Result [######]"+Style.RESET_ALL)
    
    # display table
    print(tabulate(mydata, headers=head, tablefmt="grid"))


# initialise table headings/columns name
table_header = PrettyTable([Back.LIGHTBLUE_EX+"URL/Links"+Style.RESET_ALL, Back.LIGHTBLUE_EX+"Clean"+Style.RESET_ALL, Back.LIGHTBLUE_EX+"Malicious"+Style.RESET_ALL]) 
def check_email_header(*argv):
    para = [arg for arg in argv]
    file = para[0]

    # Reading the Email header file Need to take the file as command line arguments argparse
    f = open(file)
    msg = email.message_from_file(f)
    f.close()

    print(Style.RESET_ALL)
    parser = email.parser.HeaderParser()
    headers = parser.parsestr(msg.as_string())

    meta={
        "message-id":"",
        "spf-record":False,
        "dkim-record":False,
        "dmarc-record":False,
        "spoofed":False,
        "ip-address":"",
        "sender-client":"",
        "spoofed-mail":"",
        "dt":"",
        "content-type":"",
        "subject":""
    }

    # looping the email header file contents
    ipv6_regx = "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
    for h in headers.items():

        # Message ID
        if h[0].lower()=="message-id":
            meta["message-id"]=h[1]


        # Mail server sending the mail
        if h[0].lower()=="received":
            meta["sender-client"]=h[1]

        # Authentication detected by mail server
        if h[0].lower()=="authentication-results":

            if(re.search("spf=pass",h[1])):
                meta["spf-record"]=True;

            if(re.search("dkim=pass",h[1])):
                meta["dkim-record"]=True
        
            if(re.search("dmarc=pass",h[1])):
                meta["dmarc-record"]=True

            if(re.search("does not designate",h[1])):
                meta["spoofed"]=True

            if(re.search("(\d{1,3}\.){3}\d{1,3}", h[1])!=None):
                ip=re.search("(\d{1,3}\.){3}\d{1,3}", h[1])
                meta["ip-address"]=str(ip.group())
                
            if(re.search(ipv6_regx, h[1])!=None):
                ip=re.search(ipv6_regx, h[1])
                meta["ip-address"]=str(ip.group())

        if h[0].lower()=="reply-to":
            meta["spoofed-mail"]=h[1]

        if h[0].lower()=="date":
            meta["dt"]=h[1]

        if h[0].lower()=="content-type":
            meta["content-type"]=h[1]

        if h[0].lower()=="subject":
            meta["subject"]=h[1]

    print(Fore.BLACK+Back.BLUE+"=================================== Report ==================================="+Style.RESET_ALL)

    # initialise table headings/columns name
    email_header = PrettyTable([Back.LIGHTBLUE_EX+"Email Header"+Style.RESET_ALL, Back.LIGHTBLUE_EX+"Data"+Style.RESET_ALL])

    # Add rows
    email_header.add_row([Back.GREEN+"[+] Message ID: "+Style.RESET_ALL,Fore.GREEN+meta["message-id"]+Style.RESET_ALL])

    print()

    if(meta["spf-record"]):
        email_header.add_row([Back.GREEN+"[+] SPF Records: "+Style.RESET_ALL,Fore.GREEN+"PASS"+Style.RESET_ALL])
    else:
        email_header.add_row([Back.RED+"[+] SPF Records: "+Style.RESET_ALL,Fore.RED+"FAIL"+Style.RESET_ALL])

    if(meta["dkim-record"]):
        email_header.add_row([Back.GREEN+"[+] DKIM: "+Style.RESET_ALL,Fore.GREEN+"PASS"+Style.RESET_ALL])
    else:
        email_header.add_row([Back.RED+"[+] DKIM: "+Style.RESET_ALL,Fore.RED+"FAIL"+Style.RESET_ALL])

    if(meta["dmarc-record"]):
        email_header.add_row([Back.GREEN+"[+] DMARC: "+Style.RESET_ALL,Fore.GREEN+"PASS"+Style.RESET_ALL])
    else:
        email_header.add_row([Back.RED+"[+] DMARC: "+Style.RESET_ALL,Fore.RED+"FAIL"+Style.RESET_ALL])

    if(meta["spoofed"] and (not meta["spf-record"]) and (not meta["dkim-record"]) and (not meta["dmarc-record"])):
        email_header.add_row([Back.RED+"[+] Spoofed Email Received"+Style.RESET_ALL,"-----"])
        email_header.add_row([Back.RED+"[+] Mail"+Style.RESET_ALL,Fore.RED+meta["spoofed-mail"]+Style.RESET_ALL])
        email_header.add_row([Back.RED+"[+] [+] IP-Address"+Style.RESET_ALL,Fore.RED+meta["ip-address"]+Style.RESET_ALL])
    else:
        email_header.add_row([Back.GREEN+"[+] Authentic Email Received"+Style.RESET_ALL,"-----"])
        email_header.add_row([Back.GREEN+"[+] IP-Address"+Style.RESET_ALL,Fore.GREEN+meta["ip-address"]+Style.RESET_ALL])

    email_header.add_row([Back.BLUE+"[+] Date and Time"+Style.RESET_ALL,Fore.GREEN+meta["dt"]+Style.RESET_ALL])

    print(email_header)
    
    print(Fore.LIGHTGREEN_EX+"[+] Content-Type"+Style.RESET_ALL,meta["content-type"])
    print(Fore.LIGHTGREEN_EX+"[+] Subject"+Style.RESET_ALL,meta["subject"])
    print(Fore.LIGHTGREEN_EX+"[+] Provider"+Style.RESET_ALL,meta["sender-client"])

    print("\n")
    ip_lookup(meta["ip-address"])

    # for finding links and urls in email
    print("\n")
    email_body = msg.get_payload()
    try:
        links = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', email_body)
        if links:
            for link in links:
                virus_total_scan(link)
    except:
        table_header.add_row(["N/A Links"])
    
    try:
        urls = re.findall(r'https?://\S+', email_body)
        if urls:
            for url in urls:
                virus_total_scan(url)
    except:
        table_header.add_row(["N/A Links"])
    
    print('\n')
    
  
def virus_total_scan(url):
    with virustotal_python.Virustotal(api_key) as vtotal:
        try:
            resp = vtotal.request("urls", data={"url": url}, method="POST")
            url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
            report = vtotal.request(f"urls/{url_id}")
            
            attributes = report.data['attributes']['last_analysis_stats']
            reputation = report.data['attributes']['reputation']
            
            harmless = report.data['attributes']['last_analysis_stats']['harmless']
            malicious = report.data['attributes']['last_analysis_stats']['malicious']
            suspicious = report.data['attributes']['last_analysis_stats']['suspicious']
            sus = int(malicious)+int(suspicious)
            
            table_header.add_row([url,Fore.GREEN+str(harmless)+Style.RESET_ALL,Fore.RED+str(sus)+Style.RESET_ALL])
                
        except virustotal_python.VirustotalError as err:
            print(Back.YELLOW+"No result found for : ",url,Style.RESET_ALL,"\n")
            
    print(table_header)
    
    
# checking for email attachments, urls and getting hash value
def get_url_from_msg_file(file_path):
    msg = extract_msg.Message(file_path)

    if msg.body:
        # Check if there is a URL in the message body
        url = extract_url(msg.body)
        if url:
            return url

    if msg.html:
        # Check if there is a URL in the HTML body
        url = extract_url(msg.html)
        if url:
            return url

    # Check if there are any attachments with URLs
    attachments = msg.attachments
    for attachment in attachments:
        url = extract_url(attachment.data)
        if url:
            return url

    return None

def extract_url(data):
    # Extract the first URL found in the data
    import re
    url_regex = r'(https?://\S+)'
    match = re.search(url_regex, data)
    if match:
        return match.group(1)
    else:
        return None
    
def check_url(url):
     url_list = PrettyTable([Back.BLUE+"URLs Found in Email"+Style.RESET_ALL,Back.GREEN+"VT Result +ve"+Style.RESET_ALL,Back.RED+"VT Result -ve"+Style.RESET_ALL])
     with Virustotal(api_key) as vtotal:
        try:
            resp = vtotal.request("urls", data={"url": url}, method="POST")
            url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
            report = vtotal.request(f"urls/{url_id}")
            
            attributes = report.data['attributes']['last_analysis_stats']
            reputation = report.data['attributes']['reputation']
            
            harmless = report.data['attributes']['last_analysis_stats']['harmless']
            malicious = report.data['attributes']['last_analysis_stats']['malicious']
            suspicious = report.data['attributes']['last_analysis_stats']['suspicious']
            sus = int(malicious)+int(suspicious)
            
            url_list.add_row([url,Fore.GREEN+str(harmless)+Style.RESET_ALL,Fore.RED+str(sus)+Style.RESET_ALL])
                
        except virustotal_python.VirustotalError :
            url_list.add_row([url,"URL not found in VirusTotal",""])
        
     print(url_list) 
        
def check_outlook_message(file_path):
    print("\n")
    attachment_list = PrettyTable([Back.BLUE+"Attachmets Found in Email"+Style.RESET_ALL,Back.GREEN+"VT Result +ve"+Style.RESET_ALL,Back.RED+"VT Result -ve"+Style.RESET_ALL,Back.BLUE+"Sha256"+Style.RESET_ALL])
    with open(file_path, "rb") as file:
        msg = Message(file)
        for attachment in msg.attachments:
            data = attachment.data
            hashsha_256 = hashlib.sha256(data).hexdigest()
            url = f'https://www.virustotal.com/vtapi/v2/file/report?apikey={api_key}&resource={hashsha_256}'
            response = requests.get(url)
            data = response.json()
            
            if response.status_code == 200:
                if data['response_code'] == 1:
                    positives = data['positives']
                    negatives = data['total'] - positives
                    attachment_list.add_row([attachment.longFilename,Fore.GREEN+str(positives)+Style.RESET_ALL,Fore.RED+str(negatives)+Style.RESET_ALL,hashsha_256])
                else:
                    attachment_list.add_row([attachment.longFilename,"Hash not found in VirusTotal","",hashsha_256])
            else:
                print('Error making API request')
                            
    print(attachment_list) 
    print("\n")   
    
    url = get_url_from_msg_file(file_path)
    if url:
        check_url(url)
    else:
        print("No URL found in the .msg file.")
    
    


# defining our main function and commandline argunments value
def main():
    print("""
         
███╗░░░███╗██╗░░░██╗██████╗░░█████╗░██████╗░██╗
████╗░████║██║░░░██║██╔══██╗██╔══██╗██╔══██╗██║
██╔████╔██║██║░░░██║██████╔╝███████║██████╔╝██║
██║╚██╔╝██║██║░░░██║██╔══██╗██╔══██║██╔══██╗██║
██║░╚═╝░██║╚██████╔╝██║░░██║██║░░██║██║░░██║██║
╚═╝░░░░░╚═╝░╚═════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚═╝╚═╝ 
          """)
    print(Fore.BLUE+Back.WHITE+"\nBy: Asim Tara Pathak | A tool to analyze email and email header file.\n"+Style.RESET_ALL)

    print()

    parser = optparse.OptionParser("Usage of program: "+" \n-f <email header file> Enter email header file (.eml)"+" \n-o <outlook message file> Enter outlook email file (.msg)")
    parser.add_option("-f","--file", action="store", dest="email_header_file", type="string", help="Specify the email header file",default=False)
    parser.add_option("-o","--outlook", action="store", dest="outlook_message", type="string", help="Specify the outlook message file",default=False)
    (options,args) = parser.parse_args()

    email_header_file = options.email_header_file
    outlook_message = options.outlook_message
    
    if email_header_file:
        try: 
            check_email_header(email_header_file)
        except BaseException:
            print(Fore.BLACK+Back.YELLOW+"Oops!! An Error Occured while connecting to Internet.\nPlease check your network connection and try again if you want to get iplookup and ip location track."+Style.RESET_ALL)
            print()
    elif outlook_message:
        check_outlook_message(outlook_message)     
        exit()
    else:
        print(parser.usage)
        exit()        

if __name__=="__main__":
    main()
