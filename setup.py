#!/usr/bin/env python

from distutils.core import setup

from setuptools import find_packages
__VERSION__ = "0.3.1"

setup(name='a10ctl',
      classifiers = [],
      version=__VERSION__,
      description='Command line tool managing servers on A10 Network Load Balancer',
      install_requires=[
          'cryptography==1.7.1',
          'hash-ring==1.3.1',
          'requests==2.12.4',
          'terminaltables==3.1.0',
      ],
      url="https://github.com/tarunlalwani/a10ctl.git",
      author="Tarun Lalwani",
      author_email="tarunlalwani@gmail.com",
      packages=find_packages(exclude=["conf", "dist", "build", "*.egg-info"]),
      keywords= ["a10","a10ctl", "load", "balancer"],
      download_url = 'https://github.com/tarunlalwani/a10ctl/archive/' + __VERSION__ +  '.tar.gz',
      entry_points={
          'console_scripts': ['a10ctl = a10ctl.cli:cli']
      },
      )
