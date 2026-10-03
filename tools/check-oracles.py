import ctypes, ctypes.util, json, platform, subprocess
from pathlib import Path
root = Path(__file__).resolve().parents[1]
f = json.loads((root / 'fixtures/experiment.json').read_text())
sodium = ctypes.CDLL(ctypes.util.find_library('sodium'))
sodium.sodium_init()
sodium.sodium_version_string.restype = ctypes.c_char_p
sodium.crypto_sign_verify_detached.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p]
sodium.crypto_sign_verify_detached.restype = ctypes.c_int
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
pk = bytes.fromhex(f['publicKey'])
key = Ed25519PublicKey.from_public_bytes(pk)
rows=[]
for name, signature, message, want in [('canonical',f['canonical'],f['message'],True),('hostile',f['hostile'],f['message'],False),('ordinary-message-bit-flip',f['canonical'],f['negativeMessage'],False)]:
 sig=bytes.fromhex(signature); msg=bytes.fromhex(message)
 sodium_accept=sodium.crypto_sign_verify_detached(sig,msg,len(msg),pk)==0
 try: key.verify(sig,msg); openssl_accept=True
 except cryptography.exceptions.InvalidSignature: openssl_accept=False
 assert sodium_accept == openssl_accept == want, name
 rows.append({'case':name,'OpenSSL':openssl_accept,'libsodium':sodium_accept,'signature':signature,'message':message})
L=2**252+27742317777372353535851937790883648493
assert f['canonical'][:64]==f['hostile'][:64]
assert int.from_bytes(bytes.fromhex(f['hostile'][64:]),'little')-int.from_bytes(bytes.fromhex(f['canonical'][64:]),'little')==L
assert 0<=int.from_bytes(bytes.fromhex(f['canonical'][64:]),'little')<L
assert int.from_bytes(bytes.fromhex(f['hostile'][64:]),'little')<2**256
for v in json.loads((root/'fixtures/rfc8032.json').read_text()):
 Ed25519PublicKey.from_public_bytes(bytes.fromhex(v['publicKey'])).verify(bytes.fromhex(v['signature']),bytes.fromhex(v['message']))
 assert sodium.crypto_sign_verify_detached(bytes.fromhex(v['signature']),bytes.fromhex(v['message']),len(bytes.fromhex(v['message'])),bytes.fromhex(v['publicKey']))==0
report={'command':'python3 tools/check-oracles.py','python':platform.python_version(),'cryptography':cryptography.__version__,'OpenSSL':backend.openssl_version_text(),'libsodium':sodium.sodium_version_string().decode(),'lineage':'OpenSSL Ed25519 and libsodium ref10; neither imports the lab verifier.','results':rows,'RFC8032VectorsVerified':5,'longMessageBytes':1023}
(root/'fixtures/oracle-transcript.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
