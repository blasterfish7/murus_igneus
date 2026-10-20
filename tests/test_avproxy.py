import socket,sys,threading,unittest
from pathlib import Path
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src/murus_igneus'))
from avproxy import create_proxy

class ProxyTests(unittest.TestCase):
 def conditional_request(self, status):
  response=Mock(status=status)
  response.getheader.side_effect=lambda name,default=None:default
  response.read.return_value=b'clean download'
  response.getheaders.return_value=[]
  upstream=Mock();upstream.getresponse.return_value=response
  scan=Mock(return_value=(True,'clean'))
  config={'clients':['127.0.0.0/8'],'upstream_networks':[],'blocked_domains':[]}
  server=create_proxy(config,scan,('127.0.0.1',0));thread=threading.Thread(target=server.serve_forever,daemon=True)
  try:
   with patch('avproxy.socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',80))]),patch('avproxy.local_addresses',return_value=set()),patch('avproxy.http.client.HTTPConnection',return_value=upstream):
    thread.start()
    with socket.socket() as client:
     client.settimeout(3);client.connect(server.server_address)
     client.sendall(b'GET http://example.com/file HTTP/1.0\r\nHost: example.com\r\nIf-None-Match: old\r\nIf-Modified-Since: Thu, 01 Jan 2026 00:00:00 GMT\r\n\r\n')
     data=b''
     while True:
      part=client.recv(4096)
      if not part:break
      data+=part
    return data,upstream,scan
  finally:server.shutdown();server.server_close();thread.join(3)

 def test_conditional_headers_cannot_reuse_unscanned_cache(self):
  data,upstream,scan=self.conditional_request(200)
  self.assertIn(b'200',data.splitlines()[0])
  headers={k.lower() for k in upstream.request.call_args.kwargs['headers']}
  self.assertNotIn('if-none-match',headers);self.assertNotIn('if-modified-since',headers)
  scan.assert_called_once_with(b'clean download')

 def test_upstream_304_is_blocked_without_a_full_scan(self):
  data,_,scan=self.conditional_request(304)
  self.assertIn(b'502',data.splitlines()[0]);scan.assert_not_called()

 def test_encoded_download_cannot_bypass_scanner(self):
  response=Mock(status=200)
  response.getheader.side_effect=lambda name,default=None:'br' if name=='Content-Encoding' else default
  upstream=Mock();upstream.getresponse.return_value=response
  scan=Mock(return_value=(True,'clean'))
  config={'clients':['127.0.0.0/8'],'upstream_networks':[],'blocked_domains':[]}
  server=create_proxy(config,scan,('127.0.0.1',0));thread=threading.Thread(target=server.serve_forever,daemon=True)
  try:
   with patch('avproxy.socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',80))]),patch('avproxy.local_addresses',return_value=set()),patch('avproxy.http.client.HTTPConnection',return_value=upstream):
    thread.start()
    with socket.socket() as client:
     client.settimeout(3);client.connect(server.server_address);client.sendall(b'GET http://example.com/file HTTP/1.0\r\nHost: example.com\r\n\r\n')
     data=client.recv(4096)
    self.assertIn(b'502',data.splitlines()[0]);scan.assert_not_called();response.read.assert_not_called()
  finally:server.shutdown();server.server_close();thread.join(3)

