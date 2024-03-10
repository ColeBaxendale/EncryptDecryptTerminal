from setuptools import setup, find_packages

setup(
    name='fast-crypt',
    version='0.1.0', 
    author='Cole Baxendale',
    author_email='thecodercole@gmail.com',
    description='A CLI tool for encrypting and decrypting files using GitHub authentication, with support for Google Cloud Secret Manager.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/ColeBaxendale/Fast-Crypt',
    packages=find_packages(),
    install_requires=[
        'click>=7.0',  # For CLI interactions
        'cryptography>=3.4.7',  # For encryption and decryption functionalities
        'google-cloud-secret-manager>=2.7.0',  # To interact with Google Cloud Secret Manager
        'requests>=2.25.1',  # For making HTTP requests, e.g., GitHub OAuth
        'prompt_toolkit>=3.0.18',  # For interactive command-line prompts
    ],
    entry_points={
        'console_scripts': [
            'fast_crypt=cli:main',  
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',  
)
