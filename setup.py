from setuptools import setup, find_packages

setup(
    name="kingpepe-sdk",
    version="1.1",
    packages=find_packages(),
    install_requires=["bitcoinlib", "requests"],
    author="KingPepe Dev",
    description="SDK for interacting with KingPepe blockchain",
    url="https://github.com/kingpepe2/kingpepe-sdk",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
)
