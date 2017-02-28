from base64 import urlsafe_b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from .encryption import hkdf, create_info


def get_private_key(pem_location, password=None, generate=False):
    """
    Get private key from PEM file.

    :param pem_location: Location of PEM file.
    :type pem_location: str
    :param password: Password of PEM file. None if not encrypted.
    :type password: bytes
    :param generate: if True and PEM does not exist, generate PEM file.
    :return: ec.EllipticCurvePrivateKey instance
    """

    try:
        private_key_pem = open(pem_location, 'rb').read()
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=password,
            backend=default_backend()
        )
    except FileNotFoundError as e:
        if generate:
            try:
                algorithm = serialization.BestAvailableEncryption(password)
            except ValueError as e:
                if password is None:
                    algorithm = serialization.NoEncryption()
                else:
                    raise e
            pem = open(pem_location, 'wb')
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=algorithm
            )
            pem.write(private_key_pem)
        else:
            raise e

    return private_key


def encode_public_key(public_key):
    """
    Encode public key to URL-safe Base64 format.

    :param public_key: A public key to encode
    :type public_key: ec.EllipticCurvePublicKey
    :return: URL-safe Base64 encoded public key (see SEC1 section 2.3.3)
    """
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return urlsafe_b64encode(public_key.public_numbers().encode_point()).decode('utf-8')
    else:
        raise TypeError('%r must be an instance of EllipticCurvePublicKey' % public_key)


def dump_private_key(private_key):
    # DEBUG USE ONLY
    # Return URL-safe Base64 encoding of
    # the octet string representation of the private key value, as defined
    # in Section 2.3.7 of SEC1 [SEC1].
    private_key_value = private_key.private_numbers().private_value
    return urlsafe_b64encode(private_key_value.to_bytes(32, byteorder='big')).decode('utf-8')


def fill_padding(base64):
    """
    Fill missing padding (=) in base64 encoded string/bytes.

    :param base64: Base64 encoded str/bytes
    :return: Correctly padded base64 encoded str/bytes
    """
    try:
        base64 += b'=' * (len(base64) % 4)
    except TypeError:
        try:
            base64 += '=' * (len(base64) % 4)
        except TypeError:
            raise TypeError('%r must be an instance of bytes or str' % base64)

    return base64
