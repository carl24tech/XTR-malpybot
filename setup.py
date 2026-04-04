

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = f.read().splitlines()

setup(
    name="xtr-malware-scanner",
    version="1.0.0",
    author="XTR Softwares",
    author_email="security@xtrsoftwares.com",
    description="Professional Malware Scanner for Terminal - XTR Softwares",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/xtrsoftwares/malware-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Security Professionals",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "xtr-scan=xtr_scanner.cli:main",
            "xtr-malware-scanner=xtr_scanner.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "xtr_scanner": ["signatures/*.json", "database/*.db"],
    },
)
