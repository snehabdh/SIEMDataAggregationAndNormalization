from setuptools import setup, find_packages

setup(
    name="ngsdan",                 # Package name
    version="1.0.0",                   # Package version
    description="To receive syslog on udp and host the logs through API",  # Short description
    long_description=open("README.md").read(),    # Long description from README
    long_description_content_type="text/markdown",
    author="Sneha Gupta",                # Author's name
    author_email="sneha.gupta.hbti@gmail.com", # Author's email
    url="https://github.com/yourusername/my_project", # Project URL
    license="MIT",                     # License type
    packages=find_packages(),          # Automatically find packages
    install_requires=[                 # Dependencies
        "flask>=3.1.0",
    ],
    classifiers=[                      # Metadata for package discovery
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",           # Minimum Python version
    entry_points={
        'console_scripts': [
            'ngsdan=ngsdan.main:main',  # 'command=package.module:function'
        ],
    },
)
