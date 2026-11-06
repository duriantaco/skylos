import ssl
from urllib.request import HTTPSHandler

def build_handler():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    alias = context
    alias.check_hostname = False
    return HTTPSHandler(context=context)
