from os import path
from setuptools import setup, find_packages

import ntdissector


here = path.abspath(path.dirname(__file__))
with open(path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

with open(path.join(here, "requirements.txt"), encoding="utf-8") as f:
    requirements = [line.strip() for line in f.readlines()]


setup(
    name="ntdissector",
    version=ntdissector.__version__,
    description="NTDissector",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/synacktiv/ntdissector",
    author="Synacktiv",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    keywords="ntdissector ntds esedb",
    packages=find_packages(),
    python_requires=">=3.5, <4",
    install_requires=requirements,
    entry_points={
        "console_scripts": ["ntdissector = ntdissector.__main__:main"],
    },
    project_urls={
        "Apply!": "https://www.synacktiv.com",
        "Source": "https://github.com/synacktiv/ntdissector",
    },
)
