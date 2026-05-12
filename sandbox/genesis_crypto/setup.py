"""Install marker so ``pip install /opt/crypto_primitives`` works.

The package is imported from driver scripts sent to forge_sandbox — those
scripts run with ``python -I``, which ignores PYTHONPATH, so the package
must live in site-packages. This setup.py makes that possible.
"""
from setuptools import setup

setup(
    name="genesis_crypto",
    version="0.1.0",
    packages=["genesis_crypto"],
    package_dir={"genesis_crypto": "."},
    install_requires=[],
    python_requires=">=3.10",
)
