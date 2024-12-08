#   __________________________________________________________
#  |                     [ ReconX ]                           |                         
#  |              Simple Website Recon Tool                   |                
#  |                                                          |                    
#  |              Dev ---> ISellStuff                         |            
#  |                                                          |                    
#  | If you found this tool useful consider leaving a star.   | 
#  |__________________________________________________________| 

#
#    Version 1.0
#

#
#   Command Example:
#
#   python reconx.py https://website.com
#

import os
import nmap
import requests
import argparse
from urllib.parse import urlparse
from colorama import Fore, init

init(autoreset=True)
green = Fore.GREEN
red = Fore.RED
yellow = Fore.YELLOW

# ---------------------------------------------------------- #

class ReconX:
    def __init__(self, site, server):
        """

        I normally don't add too many comments but i'll just add a some for each function because why not
        
        """

        self.site = site
        self.ip = server

    def verify(self):
        """

        Verify's if the site exists

        """

        try:
            r = requests.get(self.site)
        except:
            print(red + " [!] This website does not exist.")
            exit()

    def server(self):
        """
        
        Returns server/s ip and info
        
        """

        servers = []
        info = ""

        r = requests.post("https://www.nslookup.io/api/v1/webservers", json={"domain": self.site})
        if r.status_code != 200:
            return False
            
        sip = r.json()
        rj = sip.get("a", {}).get("response", {}).get("answer", [])

        for i in rj:
            ip = i['ipInfo']['query']
            if self.ip == None:
                self.ip = ip

            if info == "":
                country = i['ipInfo']['country']
                state = i['ipInfo']['regionName']
                provider = i['ipInfo']['org']
                info = f"Country: {country} | State: {state} | Provider: {provider}"

            servers.append(ip)

        return servers, info

    def ports(self):
        """
        
        Scans server for open ports
        
        """

        try:

            nm = nmap.PortScanner()
            nm.scan(hosts=self.ip, arguments='-p 1-1024')

            for host in nm.all_hosts():
                
                ports = []
                tcp_ports = []
                udp_ports = []
                
                if 'tcp' in nm[host]:
                    tcp_ports = list(nm[host]['tcp'].keys())
                    for i in tcp_ports:
                        ports.append(i)

                if 'udp' in nm[host]:
                    udp_ports = list(nm[host]['udp'].keys())
                    for i in udp_ports:
                        ports.append(i)

                return ports
        
        except:
            return False
        
    def headers(self):
        """
        
        Returns response headers and analyzes them
        
        """

        try:
            r = requests.get(self.site)
            headers = r.headers

            sec = [
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "X-XSS-Protection",
                "Referrer-Policy",
                "Permissions-Policy",
                "Cache-Control",
                "Access-Control-Allow-Origin"
            ]
            enabled = []
            disabled = []

            for i in sec:
                if i in headers:
                    print(green + f" [+] {i} is enabled")
                    enabled.append(i)
                else:
                    print(red + f" [!] {i} is not enabled")
                    disabled.append(i)

            return enabled, disabled

        except:
            return False

    def ssl(self):
        """
        
        Get's info about the sites ssl cert
        
        """

        domain = urlparse(self.site).netloc
        try:
            r = requests.get(f"https://ssl-checker.io/api/v1/check/{domain}")
            rj = r.json()['result']

            issuer = rj['issuer_o']
            sn = rj['cert_sn']
            valid = rj['cert_valid']
            expires = rj['valid_till']

            return issuer, sn, valid, expires

        except:
            return False

    # -------------------- #

    def start(self):
        print(Fore.CYAN + r"""
                     ___                __  __
                    | _ \___ __ ___ _ _ \ \/ /
                    |   / -_) _/ _ \ ' \ >  < 
                    |_|_\___\__\___/_||_/_/\_\
  _________________________________________________________________

      Note: Some stuff may not be revealed during the scan                                                                  
      [+] Scaning...                                                 
  ________________________________________________________________""" + "\n")

        print(green + " [+] Verifying That The Website Exists")
        self.verify()

        print(green + " [+] Getting Info On The Servers")
        servers = self.server()
        if servers == False:
            print(red + " [!] Failed To Get Info On The Servers")
        else:
            print(green + " [+] Scanning For Open Ports")

        ports = self.ports()
        if ports == False:
            print(red + " [!] Failed To Scan For Open Ports")
        else:
            print(green + f" [+] Ports Open: {len(ports)}")

        print(green + " [+] Analyzing Headers")
        headers = self.headers()
        if headers == False:
            print(red + " [!] Failed To Make A Request")

        print(green + " [+] Getting Info About SSL Cert")
        ssl = self.ssl()
        if ssl == False:
            print(red + " [!] Failed To Return Info On The SSL Cert | It's likely that this site does not have a ssl cert")

        print(green + "\n [!] Scan Complete")
        data = f"""
_________________________________________________________________________________________________________________

 Target --> {self.site}

\n
        Server Info

 Servers: {servers[0]}                                                            
 Server Info: {servers[1]}                                      
 Open Ports: {ports} 

\n
        Security Headers
                     
 Enabled Sec Headers: {headers[0]}
 Disabled Sec Headers: {headers[1]}

\n
        SSL Cert Info
        
 Issuer: {ssl[0]}
 Serial Number: {ssl[1]}
 Valid: {ssl[2]}
 Expires In: {ssl[3]}
_________________________________________________________________________________________________________________
"""
        print(Fore.CYAN + data)
        save = input(Fore.CYAN + "Do You Want To Save The Results? y/n > ")
        if save == "y":
            with open("data.txt", "w") as f:
                f.write(data)

        return

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-u', '--url', type=str, required=True)
    args = parser.parse_args()

    reconx = ReconX(args.url, None)
    reconx.start()

# ---------------------------------------------------------- #

if __name__ == "__main__":
    main()
