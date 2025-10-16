import base64, hashlib, os

def generate_code_verifier():
    return base64.urlsafe_b64encode(os.urandom(40)).rstrip(b'=').decode('utf-8')

def code_challenge_from_verifier(verifier):
    m = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(m).rstrip(b'=').decode('utf-8')
