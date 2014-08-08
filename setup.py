from setuptools import setup


with open('README.rst', 'r') as infile:
    long_description = infile.read()

with open('requirements.txt', 'r') as infile:
    install_requires = infile.read().split()

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
    version='0.0.0',
    #setup_requires=['vcversioner>=1'],
    #vcversioner={
    #    'version_module_paths': ['i2p/i2cp/_version.py'],
    #},
    #install_requires=install_requires,
    packages=['i2p.i2cp', 'i2p.i2cp.test', 'i2p'],
)
