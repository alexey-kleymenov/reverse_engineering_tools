# Super Simple HTTP Honeypot
This is an extremely simple honeypot that opens common HTTP ports and logs all incoming requests to the console. It records:
* HTTP request types
* Source IP addresses
* URL paths requested
* HTTP headers
* POST bodies (if any)

Each line is in the JSON format to enable easy parsing by automation.

Always exercise extreme caution when deploying honeypots because of potential malware escape, the authors takes no responsibility for any potential damage caused.

# Installation
1. Use non-root account on a dedicated machine separated from any important networks
2. Set up port forwarding to make port 80 visible to attackers
```
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
```
3. Run the honeypot
```
python3 http_honeypot.py | tee -a log.txt
```
