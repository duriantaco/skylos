import ssl
from urllib.request import HTTPSHandler

context = ssl.SSLContext(ssl.PROTOCOL_TLS)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True
handler = HTTPSHandler(context=context)
