from base64 import urlsafe_b64encode as b64encode, urlsafe_b64decode as b64decode
from datetime import datetime, timedelta
from urllib import parse

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import jwt
import requests

from .utils import fill_padding
from .encryption import encrypt_data


class Notification(object):
    TTL = 300  # Time to live in seconds (in push service)
    expire_after = 86400  # VAPID message will expire after this (in seconds)
    vapid_private_key = None  # Server private key used to generate applicationServerKey
    sender = None  # Sender of the notification, either in mailto: URI or generic URL

    def __init__(self, subscription, message=None, sender=None, private_key=None, ttl=None, expire_after=None):
        """
        Initialize a Notification instance using given parameters.

        :param subscription: PushSubscription object which can be obtained from client.
        :type subscription: dict
        :param message: Message to send
        :type message: str or bytes
        :param sender: Sender of the notification, either in mailto: URI or generic URL
        :type sender: str
        :param private_key: Server private key used to sign VAPID claims (which also generated applicationServerKey)
                            if this is None, VAPID won't be attached to Push Message.
        :type private_key: ec.EllipticCurvePrivateKey
        :param ttl: Time to live (in push service)
        :type ttl: int
        :param expire_after: VAPID message will expire after this (in seconds)
        :type expire_after: int
        """
        try:
            self.endpoint = subscription['endpoint']
            self.p256dh = b64decode(fill_padding(subscription['keys']['p256dh']))
            self.auth_secret = b64decode(fill_padding(subscription['keys']['auth']))
        except KeyError as e:
            raise KeyError('Missing key in subscription object: %r' % e.args[0])

        if isinstance(message, bytes):
            self.message = message
        elif isinstance(message, str):
                self.message = message.encode('utf-8')
        elif message is None:
            self.message = None
        else:
            raise TypeError('%r must be bytes or str or None' % message)

        if private_key is not None:
            self.vapid_private_key = private_key
        if ttl is not None:
            self.TTL = ttl
        if expire_after is not None:
            self.expire_after = expire_after
        if sender is not None:
            self.sender = sender

    def generate_claims(self):
        """
        Generate claims using instance's attribute.

        :return: VAPID claims in dict
        """
        parsed_endpoint = parse.urlparse(self.endpoint)
        expires_at = (datetime.now() + timedelta(seconds=self.expire_after)).timestamp()
        assert self.sender is not None, 'VAPID claims cannot be generated without sender.'
        return {
            'aud': parsed_endpoint.scheme + '://' + parsed_endpoint.netloc,
            'exp': str(int(expires_at)),
            'sub': self.sender
        }

    def send(self):
        if self.message is not None:
            headers, ciphertext = encrypt_data(self.p256dh, self.auth_secret, self.message)
        else:
            headers = {'Content-Length': '0'}
            ciphertext = b''
        headers['TTL'] = str(self.TTL)
        if self.vapid_private_key is not None:
            vapid_public_key_b64 = (
                b64encode(
                    self.vapid_private_key.public_key().public_bytes(
                        Encoding.X962, PublicFormat.UncompressedPoint
                    )
                )
                .decode("utf-8")
                .strip("=")
            )
            signed_claim = sign_vapid(self.generate_claims(), self.vapid_private_key)
            headers[
                "Authorization"
            ] = "vapid t={signed_claim}, k={vapid_signing_key}".format(
                signed_claim=signed_claim, vapid_signing_key=vapid_public_key_b64
            )
        return requests.post(self.endpoint, headers=headers, data=ciphertext)


def sign_vapid(claims, private_key):
    """
    Sign a VAPID claims using given private key.

    :param claims: Dictionary of claims to sign.
    :type claims: dict
    :param private_key: Server's private key used to sign claims.
    :type private_key: ec.EllipticCurvePrivateKey
    :return: Encoded VAPID in str
    """
    return jwt.encode(claims, private_key, algorithm="ES256").decode('utf-8')


def send_notification(subscription, data, sender=None, private_key=None):
    """
    A wrapper function for initializing & sending notification.

    :param subscription: client's subscription
    :param data: An actual data to send
    :param sender: (Optional) VAPID claims sender
    :param private_key: (Optional) VAPID private key
    :return: Response object received from Push Service
    """
    noti = Notification(subscription, data, sender=sender, private_key=private_key)
    return noti.send()
