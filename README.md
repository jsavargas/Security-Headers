# Security Headers

HTTP Security Headers 



##### Finds the security headers that are not enabled in a specific domain.
```
$ python3 securityHeaders.py -t https://google.com
 [+] X-XSS-Protection => 0
 [+] X-Frame-Options => SAMEORIGIN
 
 [!] Strict-Transport-Security 
 [!] X-Content-Type-Options 
 [!] Content-Security-Policy 
 [!] Public-Key-Pins 
 [!] X-Permitted-Cross-Domain 
 [!] Referrer-Policy 
 [!] Expect-CT 
 [!] Feature-Policy 
 [!] Content-Security-Policy-Report-Only 
 [!] Expect-CT 
 [!] Public-Key-Pins-Report-Only 
 [!] Upgrate-Insecure-Requests 
 [!] X-Powered-By 

```


### HTTP Security Headers List

you can detect the following HTTP security headers:

* Strict-Transport-Security
* X-XSS-Protection
* X-Content-Type-Options
* X-Frame-Options
* Content-Security-Policy
* Public-Key-Pins
* X-Permitted-Cross-Domain
* Referrer-Policy
* Expect-CT
* Feature-Policy
* Content-Security-Policy-Report-Only
* Expect-CT
* Public-Key-Pins-Report-Only
* Upgrate-Insecure-Requests
* X-Powered-By

**note:** you can add security headers by directly modifying the code.

### INSTALL

```
pip install -r requirements.txt
```

### USAGE

The use is very simple.

```
python3 securityHeaders.py -t https://google.com

docker run --rm jsavargas/securityheaders python3 securityHeaders.py -t https://google.com 

```
