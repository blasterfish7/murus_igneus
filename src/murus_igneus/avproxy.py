"""Explicit HTTP download proxy; antivirus fails closed. SPDX-License-Identifier: MIT."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlsplit
import http.client
import ipaddress as ip
import socket
import threading

LIMIT=20*1024**2
SEMAPHORE=threading.BoundedSemaphore(4)
HOP={'connection','proxy-connection','proxy-authorization','proxy-authenticate','keep-alive','transfer-encoding','te','trailer','upgrade','content-length','host','accept-encoding','range','if-range'}

def create_proxy(config,scan):
    clients=[ip.IPv4Network(n) for n in config['clients']]
    allowed=[ip.IPv4Network(n) for n in config['upstream_networks']]
    domains=config['blocked_domains']
    class Proxy(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.0'
        server_version='Murus-HTTP-AV/0.3'
        timeout=30
        def log_message(self,*_):pass
        def do_CONNECT(self):self.send_error(501,'HTTPS inspection is not available; CONNECT is disabled')
        def do_POST(self):self.send_error(405,'Only HTTP GET and HEAD downloads are supported')
        def do_HEAD(self):self.do_GET()
        def do_GET(self):
            if not any(ip.IPv4Address(self.client_address[0]) in n for n in clients):return self.send_error(403,'Client not authorized')
            if not SEMAPHORE.acquire(blocking=False):return self.send_error(503,'Proxy busy')
            upstream=None
            try:
                url=urlsplit(self.path)
                if url.scheme!='http' or not url.hostname or url.username or url.password or url.fragment: return self.send_error(400,'Use an absolute HTTP URL')
                host=url.hostname.lower().rstrip('.')
                if any(host==d or host.endswith('.'+d) for d in domains):return self.send_error(403,'Domain blocked')
                candidates={r[4][0] for r in socket.getaddrinfo(host,url.port or 80,socket.AF_INET,socket.SOCK_STREAM)}
                safe=[a for a in candidates if (ip.IPv4Address(a).is_global or any(ip.IPv4Address(a) in n for n in allowed)) and not ip.IPv4Address(a).is_loopback and not ip.IPv4Address(a).is_link_local and not ip.IPv4Address(a).is_multicast and a not in local_addresses()]
                if not safe:return self.send_error(403,'Destination is not authorized')
                # Connect to the validated IP, avoiding a second DNS lookup/rebinding.
                upstream=http.client.HTTPConnection(sorted(safe)[0],url.port or 80,timeout=30)
                headers={k:v for k,v in self.headers.items() if k.lower() not in HOP}
                headers['Host']=url.netloc;headers['Connection']='close';headers['Accept-Encoding']='identity'
                upstream.request('GET',(url.path or '/')+('?' +url.query if url.query else ''),headers=headers)
                response=upstream.getresponse();body=response.read(LIMIT+1)
                if len(body)>LIMIT:return self.send_error(413,'Download exceeds the antivirus scanning limit')
                clean,message=scan(body)
                if not clean:return self.send_error(403,'Antivirus blocked the download')
                self.send_response(response.status)
                for k,v in response.getheaders():
                    if k.lower() not in HOP and k.lower() not in ('content-range','accept-ranges'):self.send_header(k,v)
                self.send_header('Content-Length',str(len(body)));self.send_header('Connection','close');self.end_headers()
                if self.command!='HEAD':self.wfile.write(body)
            except Exception:self.send_error(502,'Download or antivirus verification failed; content not delivered')
            finally:
                if upstream:upstream.close()
                SEMAPHORE.release()
    return ThreadingHTTPServer(('0.0.0.0',3128),Proxy)

def local_addresses():
    # Never allow the proxy to target the appliance's management/control endpoints.
    import json,subprocess
    return {a['local'] for i in json.loads(subprocess.check_output(['ip','-j','-4','addr'],text=True)) for a in i.get('addr_info',[])}
