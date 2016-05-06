# -*- coding: utf-8 -*-
import os

from setuptools import setup
from setuptools.extension import Extension

from utp import VERSION

libutp_dir = os.path.join("libutp")

sources = [
    os.path.join(libutp_dir, "utp_api.cpp"),
    os.path.join(libutp_dir, "utp_callbacks.cpp"),
    os.path.join(libutp_dir, "utp_hash.cpp"),
    os.path.join(libutp_dir, "utp_internal.cpp"),
    os.path.join(libutp_dir, "utp_packedsockaddr.cpp"),
    os.path.join(libutp_dir, "utp_utils.cpp"),
]
include_dirs = [
    os.path.join(libutp_dir)
]
define_macros = []
libraries = []
extra_link_args = []

if os.name == "nt" or os.name == "win32":
    define_macros.append(("WIN32", 1))
    libraries.append("ws2_32")
    sources.append(os.path.join(libutp_dir, "libutp_inet_ntop.cpp"))
else:
    define_macros.append(("POSIX", 1))
    r = os.system('echo "int main() {}"|gcc -x c - -lrt 2>/dev/null')
    if r == 0:
        libraries.append("rt")

# http://bugs.python.org/issue9023
sources = [os.path.abspath(x) for x in sources]

ext = Extension(
    name="pyutp",
    sources=sources,
    include_dirs=include_dirs,
    libraries=libraries,
    define_macros=define_macros,
    extra_link_args=extra_link_args
)

setup(
    name="pyutp",
    version=VERSION,
    description="The uTorrent Transport Protocol library",
    author="Greg Hazel",
    author_email="greg@bittorrent.com",
    maintainer="Greg Hazel",
    maintainer_email="greg@bittorrent.com",
    url="http://github.com/bittorrent/libutp",
    packages=['pyutp',
              'pyutp.tests'],
    ext_modules=[ext],
    zip_safe=False,
    license='MIT'
)
