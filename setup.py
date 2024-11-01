import setuptools
from ptmultifinder._version import __version__

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="ptmultifinder",
    version=__version__,
    description="Custom Source Domain Testing Tool",
    author="Penterep",
    author_email="info@penterep.com",
    url="https://www.penterep.com/",
    license="GPLv3+",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: Implementation :: CPython",
        "Environment :: Console",
        "Topic :: Security",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)"
    ],
    python_requires='>=3.9',
    install_requires=["ptlibs>=1.0.7,<2"],
    entry_points = {'console_scripts': ['ptmultifinder = ptmultifinder.ptmultifinder:main']},
    long_description=long_description,
    long_description_content_type="text/markdown",
    project_urls = {
    "homepage":   "https://www.penterep.com/",
    "repository": "https://github.com/penterep/ptmultifinder",
    "tracker":    "https://github.com/penterep/ptmultifinder/issues",
    }
)