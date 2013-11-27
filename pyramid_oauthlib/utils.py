import base64
from oauthlib.common import bytes_type, to_unicode


def decode_base64(text):
    """Decode base64 string."""
    # make sure it is bytes
    if not isinstance(text, bytes_type):
        text = text.encode('utf-8')
    return to_unicode(base64.b64decode(text), 'utf-8')