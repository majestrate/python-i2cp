from setuptools import setup
import os

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

if 'TOXENV' in os.environ:
    version = '0.0.0-tox'
else:
    version = None


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
    setup_requires=(not version and ['vcversioner>=1'] or []),
    vcversioner=(not version and {
        'version_module_paths': ['i2p/i2cp/_version.py'],
        'root': os.path.dirname(os.path.abspath(__file__)),
    } or None),
    install_requires=install_requires,
    packages=['i2p.i2cp', 'i2p.i2cp.test'],
)
