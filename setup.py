from setuptools import setup, find_packages

setup(
    name="cyhy-core",
    version="0.0.2",
    author="Mark Feldhousen Jr.",
    author_email="mark.feldhousen@cisa.dhs.gov",
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    scripts=[
        "bin/cyhy-archive",
        "bin/cyhy-control",
        "bin/cyhy-domain",
        "bin/cyhy-export",
        "bin/cyhy-geoip",
        "bin/cyhy-import",
        "bin/cyhy-ip",
        "bin/cyhy-kevsync",
        "bin/cyhy-mongo",
        "bin/cyhy-nvdsync",
        "bin/cyhy-sched",
        "bin/cyhy-simple",
        "bin/cyhy-snapshot",
        "bin/cyhy-suborg",
        "bin/cyhy-ticket",
        "bin/cyhy-tool",
    ],
    # url='http://pypi.python.org/pypi/cyhy/',
    license="LICENSE.txt",
    description="Core scanning libraries for Cyber Hygiene",
    long_description=open("README.md").read(),
    install_requires=[
        "docopt >= 0.6.2",
        "geoip2 >= 2.3.0",
        "maxminddb <2.0.0",
        "mongokit >= 0.9.0",
        "netaddr >= 0.7.10",
        "pandas >= 0.16.2",  # TODO: test with 0.19.1
        "progressbar >=2.3-dev",
        "pycrypto >= 2.6",
        "pymongo >= 2.9.2, < 3",
        "python-dateutil >= 2.2",
        "PyYAML >= 3.12",
        "six >= 1.9",
        "validators >= 0.14.6",
    ],
    extras_require={"dev": ["ipython >= 5.8.0", "mock >= 2.0.0"]},
)
