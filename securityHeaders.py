#!/usr/bin/env python3
#_*_ coding: utf8 _*_


try:
    import requests
    import argparse
    from prettytable import PrettyTable
    from textwrap import fill
    import sys
except ImportError as err:
    print("Some libraries are missing:")
    print(err)
    
parser = argparse.ArgumentParser(description="Security Headers ")
parser.add_argument('-t','--target',help="example: python -t https://www.domain.com")
parser.add_argument('-v','--verbose',action='store_true',help="show all information from headers")
parser.add_argument('-o','--output',help="save report in a file.")
parser = parser.parse_args()






# Security headers
security_headers =['Strict-Transport-Security',
                    'X-XSS-Protection',
                    'X-Content-Type-Options',
                    'X-Frame-Options',
                    'Content-Security-Policy',
                    'Public-Key-Pins',
                    'X-Permitted-Cross-Domain',
                    'Referrer-Policy',
                    'Expect-CT',
                    'Feature-Policy',
                    'Content-Security-Policy-Report-Only',
                    'Expect-CT',
                    'Public-Key-Pins-Report-Only',
                    'Upgrate-Insecure-Requests',
                    'X-Powered-By']

table = PrettyTable()
table_info = PrettyTable()

column_names = ["HEADER", "INFORMATION"]
column_names_report = ["ENABLED SECURITY HEADERS","MISSING SECURITY HEADERS"]

def main():
    headers = []
    enabled_headers = []
    info_headers = []
    if parser.target:
        url = requests.get(url=parser.target)
        hdrs = dict(url.headers)

        for i in hdrs:
            headers.append(i)
            info_headers.append(hdrs[i])


        for k in hdrs:
            if k.lower() in [sh.lower() for sh in security_headers]:
                enabled_headers.append(k)
                print(f" [+] {k} => {hdrs[k]}")  # TODO: AGREGAR A TABLA

        missing_headers = [] 
        for sh in security_headers:
            if not sh.lower() in [h.lower() for h in headers]:
                missing_headers.append(sh)
                print(f" [!] {sh} ") # TODO: AGREGAR A TABLA

        return ""

        
    else:
        print("connection can't be established...")
        print("type python3 guillotine.py -h to show more options")
       


if __name__=='__main__':
    main()