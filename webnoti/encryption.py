from base64 import urlsafe_b64encode as b64encode
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


backend = default_backend()
curve = ec.SECP256R1()


def hkdf(salt, ikm, info, length):
    """
    Wrapper for cryptography.hazmat.primitives.kdf.hkdf.HKDF.

    :param salt: Cryptographic salt in bytes
    :param ikm: Initial keying material
    :param info: Structured data
    :param length: length of desired output key
    :return: the derived key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(ikm)


def create_info(type, client_public_key, server_public_key):
    """
    Create info structure for use in encryption.

    The start index for each element within the buffer is:
    value               | length | start    |
    -----------------------------------------
    'Content-Encoding: '| 18     | 0        |
    type                | len    | 18       |
    nul byte            | 1      | 18 + len |
    'P-256'             | 5      | 19 + len |
    nul byte            | 1      | 24 + len |
    client key length   | 2      | 25 + len |
    client key          | 65     | 27 + len |
    server key length   | 2      | 92 + len |
    server key          | 65     | 94 + len |
    For the purposes of push encryption the length of the keys will
    always be 65 bytes.

    :param type: HTTP Content Encryption Specification (must be "aesgcm")
    :param client_public_key: Client's public key in bytes
    :param server_public_key: Server's public key in bytes
    :return: generated info
    """
    if not isinstance(type, bytes):
        raise TypeError('type must be bytes')

    # The string 'Content-Encoding: ' in utf-8 encoding
    info = b'Content-Encoding: '
    # Tye 'type' of the record, encoded in utf-8
    info += type
    # null + 'P-256' (representing the EC being used) + null
    info += b'\x00P-256\x00'
    # The length of the client's public key as a 16-bit integer
    info += len(client_public_key).to_bytes(2, byteorder='big')
    # Actual client's public key
    info += client_public_key
    # The length of our public key
    info += len(server_public_key).to_bytes(2, byteorder='big')
    # Actual public key
    info += server_public_key

    return info


def encrypt_data(client_encoded_public_key, client_auth_secret, data):
    """
    Encrypt data using HTTP Encrypted Content Encoding

    :param client_encoded_public_key: Decoded subscription['keys']['p256dh']
    :param client_auth_secret: Decoded subscription['keys']['auth']
    :param data: An actual data to send (bytes)
    :return: A 2-tuple containing (headers, data), each in dict, bytes
    """
    client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        curve, client_encoded_public_key
    )

    # Generate salt
    salt = os.urandom(16)

    # Generate Server Public & Private Key pair
    server_private_key = ec.generate_private_key(curve, backend)
    server_public_key = server_private_key.public_key()
    server_public_key_bytes = server_public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    # Derive shared secret using ECDH
    shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)

    # Generate PRK (according to spec)
    auth_info = b'Content-Encoding: auth\x00'
    prk = hkdf(client_auth_secret, shared_secret, auth_info, 32)

    # Derive the Content Encryption Key
    encryption_key_info = create_info(b'aesgcm', client_encoded_public_key, server_public_key_bytes)
    encryption_key = hkdf(salt, prk, encryption_key_info, 16)

    # Derive the Nonce
    nonce_info = create_info(b'nonce', client_encoded_public_key, server_public_key_bytes)
    nonce = hkdf(salt, prk, nonce_info, 12)

    # Generate padding
    # Length of the padding, up to 65535 bytes
    padding_length = len(data) % 32
    print(padding_length)
    # Append the length of the padding to the front
    padding = padding_length.to_bytes(2, byteorder='big')
    # Repeat null to the end
    padding += b'\x00' * padding_length

    # Time to encrypt!
    encryptor = Cipher(
        algorithms.AES(encryption_key),
        modes.GCM(nonce),
        backend=backend
    ).encryptor()

    ciphertext = encryptor.update(padding + data) + encryptor.finalize() + encryptor.tag

    headers = {
        'Encryption': 'salt=' + b64encode(salt).decode('utf-8').strip('='),
        'Content-Type': 'application/octet-stream',
        'Crypto-Key': 'dh=' + b64encode(server_public_key_bytes).decode('utf-8').strip('='),
        'Content-Encoding': 'aesgcm',
        'Content-Length': str(len(ciphertext)),
    }

    return headers, ciphertext