from setuptools import setup

setup(name='scram-zeek',
    version='0.2',
    zip_safe=True,
    py_modules = ["scram_zeek"],
    install_requires=[
        "certifi",
        "requests",
        "prometheus-client",
        "walrus",
    ],
    entry_points = {
        'console_scripts': [
            'scram-zeek = scram_zeek:main',
        ]
    }
)
