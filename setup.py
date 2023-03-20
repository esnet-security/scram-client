from setuptools import setup

setup(name='scram-client',
    zip_safe=True,
    py_modules = ["scram_client"],
    install_requires=[
        "requests",
        "prometheus-client",
        "walrus",
    ],
    entry_points = {
        'console_scripts': [
            'scram-client = scram_client.cli:main',
        ]
    }
)

