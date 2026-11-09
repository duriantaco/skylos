import ssl
from urllib.request import HTTPSHandler
ssl.CERT_REQUIRED = ssl.CERT_NONE

context = ssl.SSLContext(ssl.PROTOCOL_TLS)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True
handler = HTTPSHandler(context=context)
