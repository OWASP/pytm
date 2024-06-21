import setuptools

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setuptools.setup(
    name="pytm",
    version="1.3.1",
    packages=["pytm"],
    description="A Python-based framework for threat modeling.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="pytm team",
    author_email="please_use_github_issues@nowhere.com",
    license="MIT License",
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
    python_requires=">=3",
    install_requires=["pydal>=20200714.1"],
    package_data={
        "pytm": [
            "images/datastore.png",
            "images/lambda.png",
            "images/datastore_black.png",
            "images/datastore_darkgreen.png",
            "images/datastore_firebrick3.png",
            "images/datastore_gold.png",
            "threatlib/threats.json",
        ],
    },
    exclude_package_data={"": ["report.html"]},
    include_package_data=True,
)
