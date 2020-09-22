import setuptools

setuptools.setup(
    name='pytm',
    version='1.1',
    packages=['pytm'],
    description='A Python-based framework for threat modeling.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    license='MIT License',
    url="https://github.com/izar/pytm",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Natural Language :: English",
    ],
    python_requires='>=3',
    install_requires=['pydal>=20200714.1'],
    package_data={
        'pytm': ['images/lambda.png', 'threatlib/threats.json'],
    },
    exclude_package_data={'': ['report.html']},
    include_package_data=True,
)
