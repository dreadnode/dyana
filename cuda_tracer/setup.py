from setuptools import setup, find_packages

setup(
    name="cuda_tracer",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "bcc>=0.18.0",
        "torch>=1.8.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "black>=21.0",
        ]
    },
    python_requires=">=3.8",
)
