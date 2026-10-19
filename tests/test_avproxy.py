import socket,sys,threading,unittest
from pathlib import Path
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src/murus_igneus'))
from avproxy import create_proxy

class ProxyTests(unittest.TestCase):
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
