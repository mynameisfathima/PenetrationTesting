from setuptools import setup

setup(
    name="optec",
    version="1.0.0",
    description="A tool for scanning a target URL using YAML templates.",
    author="X",
    url="https://github.com/mynameisfathima/PenetrationTesting/tree/check",
    py_modules=["main"],  # Assuming your file is named main.py
    entry_points={
        "console_scripts": [
            "optec=main:main",  # Maps the `optech` command to the `main()` function in `main.py`
        ],
    },
    install_requires=["pyyaml"],  # Add other dependencies as needed
)
