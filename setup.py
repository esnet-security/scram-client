from setuptools import setup

setup(name='scram-client',
    version='0.2',
    zip_safe=True,
    py_modules = ["scram_client"],
    install_requires=[
        "certifi",
        "requests",
        "prometheus-client",
        "walrus",
    ],
    entry_points = {
        'console_scripts': [
            'scram-client = scram_client:main',
        ]
    }
)
