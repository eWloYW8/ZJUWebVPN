from setuptools import setup, find_packages

setup(
    name="ZJUWebVPN",
    version="0.1.2",
    author="eWloYW8",
    author_email="3171132517@qq.com",
    description="A Python wrapper for Zhejiang University WebVPN",
    long_description=open('README.md', encoding='utf-8').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/eWloYW8/ZJUWebVPN",
    py_modules=["ZJUWebVPN"],
    install_requires=[
        "requests",
        "pycryptodome",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: Public Domain",
        "Operating System :: OS Independent",
    ],
    license="WTFPL",
    python_requires='>=3.6',
)
