# Setup file for PSSST
import setuptools
import re

version_line_finder = re.compile(r'__version__\s*=\s*"(\d+\.\d+(\.\d+)?)"')

with open("pssst/__init__.py", "r") as fh:
    for line in fh:
        match = version_line_finder.match(line)
        if match:
            __version__ = match.groups()[0]
            break
    else:
        print("WARNING: Version info missing from module")
        __version__ = "0.0.0"

setuptools.setup(
    name="pssst",
    version=__version__,
    author="Nicko van Someren",
    author_email="nicko@nicko.org",
    description="Packet Security for Stateless Server Transactions",
    url="https://github.com/nickovs/pssst",
    packages=setuptools.find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    install_requires=['cryptography'],
    python_requires='>=3.4',
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
    keywords=['pssst', 'security', 'crypto', 'stateless'],
)
