from setuptools import setup, find_packages

setup(
    name="skylos",
    version="0.0.8",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=["inquirer>=3.0.0"],
    entry_points={
        "console_scripts": [
            "skylos=skylos.cli:main",
        ],
    },
)