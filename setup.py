from setuptools import setup, find_packages
import ast
from os import path
import re

_version_re = re.compile(r'__version__\s+=\s+(.*)')

with open('webnoti/__init__.py', 'rb') as f:
    version = str(ast.literal_eval(_version_re.search(
        f.read().decode('utf-8')).group(1)))

root = path.abspath(path.dirname(__file__))
with open(path.join(root, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

requirements = [
    'cryptography>=2.5',
    'PyJWT',
    'requests',
]

setup(
    name='python-webnoti',
    version=version,
    description='Easy-to-use Web Push Notification Library',
    long_description=long_description,
    url='https://github.com/puilp0502/python-webnoti',
    author='Frank Yang',
    author_email='puilp0502@gmail.com',
    license='MIT',

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development :: Libraries',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    keywords='web push notification',
    packages=find_packages(exclude=['contrib', 'docs', 'tests*']),
    install_requires=requirements,
)
