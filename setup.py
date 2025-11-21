from setuptools import setup, find_packages

setup(
    name="anomaly_detector",
    version="0.1",
    packages=find_packages(where="src"),  # <- look inside src
    package_dir={"": "src"},               # <- map root to src
)
