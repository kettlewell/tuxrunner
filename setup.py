from setuptools import setup

setup(
    name='tuxrunner',
    version='1.0',
    py_modules=['tuxrunner.py'],
    install_requires=['paramiko'],
    bin=['tuxrunner.py'],
)
