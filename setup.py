from setuptools import setup
import os
import sys

long_description = ''
long_description_fname = 'README.rst'

if os.path.exists(long_description_fname):
    with open(long_description_fname, 'r') as infile:
        long_description = infile.read()


install_requires = []
install_requires_fname = 'requirements.txt'

if os.path.exists(install_requires_fname):
    with open(install_requires_fname, 'r') as infile:
        install_requires = infile.read().split()

# future is only a requirement for Py2
# This will not work on Py3 if any of the 14 standard library modules listed
# here get used later on:
# http://python-future.org/standard_library_imports.html#list-standard-library-refactored
if sys.version_info[0] < 3:
    install_requires.append('future>=0.14.0')

version = '0.0.2'

setup(
    name='i2p.i2cp',
    description='I2CP client library for I2P',
    long_description=long_description,
    author='Jeff',
    author_email='ampernand@gmail.com',
    url='https://github.com/majestrate/python-i2cp',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: Public Domain',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Internet',
    ],
    license='Public Domain',
    version=version,
    install_requires=install_requires,
    package_dir={'': 'src'},
    packages=['i2p', 'i2p.i2cp', 'i2p.socket', 'i2p.tun'],
)
