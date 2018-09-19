from setuptools import find_packages, setup
from ksm import __version__ as ksm_version
import sys

if sys.version_info < (3, 7):
    sys.exit('Python 3.7+ required')

setup(
    name='es-ksm',
    author='Casey Weed',
    author_email='cweed@caseyweed.com',
    version=ksm_version,
    description='Manage keystores for es clusters',
    url='https://github.com/battleroid/es-ksm',
    py_modules=['ksm'],
    install_requires=[
        'elasticsearch',
        'paramiko'
    ],
    entry_points="""
        [console_scripts]
        es-ksm=ksm:main
    """
)
