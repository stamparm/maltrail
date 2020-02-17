#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from os.path import join, dirname
from setuptools import setup, find_packages

script_dirname = join(dirname(__file__))

__version__ = '0.16'


def read(readme):
    return open(join(script_dirname, readme), "rb").read().decode("utf-8")


setup(
    name='maltrail',
    version=__version__,
    packages=['trails', 'maltrail'],
    package_dir={
       'trails': 'trails',
       'maltrail': 'core',
    },
    include_package_data=True,
    url='https://github.com/stamparm/maltrail',
    license='MIT',
    author='Miroslav Stampar',
    author_email='miroslav@sqlmap.org',
    description='Malicious traffic detection system',
    long_description=read('README.md'),
    long_description_content_type='text/x-markdown',
    classifiers=[
        "Development Status :: 4 - Beta",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    install_requires=[
        'odict',
        # pcapy needed for sensor.py, not yet included by setup.py
        'six',
    ],
)
