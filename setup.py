import setuptools

packages=setuptools.find_packages()

setuptools.setup(
    name='pytm',
    version='0.3',
    packages=['pytm'],
    summary='A Python-based framework for threat modeling.',
    long_description=open('README.md').read(),
    license='MIT License',
    url="https://github.com/izar/pytm",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
	"Environment :: Console",
	"Intended Audience :: Developers",
	"Topic :: Security",
    ],
    python_requires='>=3'
)
