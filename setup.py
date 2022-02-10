from pathlib import Path
from setuptools import setup, find_packages
from setuptools.extension import Extension
import sys

this_script = Path(__file__).resolve()
top_dir = this_script.parent

# Note: Depends on meson build being run beforehand.
def get_build_base():
    for arg in sys.argv:
        k, sep, v = arg.partition("=")
        if (k, sep) == ("--build-base", "="):
            return v

    return f"{top_dir}/build"

build_dir = get_build_base()

ext_modules = [
    Extension(
        "casync._casync",
        sources=["casync/_casync.pyx"],
        include_dirs=[f"{top_dir}/src"],
        extra_compile_args=["-include", f"{build_dir}/config.h"],
        library_dirs=[f"{build_dir}"],
        extra_link_args=[
            "-Wl,--as-needed",
            # XXX: Causes link failure. Figure out how to link with libpython.
            #"-Wl,--no-undefined"
        ],
        libraries=[
            "casync"
        ])
]

setup(
    name="casync",
    description="casync support for Python",
    packages=find_packages(),
    ext_modules=ext_modules,
    setup_requires=[
        "cython",
        "setuptools >= 18.0"
    ])
