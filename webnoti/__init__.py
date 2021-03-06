"""
    webnoti
    ~~~~~~~

    a python library for sending web notification
    It tries to be simple, concise, but still extensive.
"""

__version__ = '0.3.0'

from .notification import send_notification, Notification
from .utils import get_private_key
