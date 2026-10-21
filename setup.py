from setuptools import setup, find_packages

setup(
    name="attack-surface-mapper",
    version="1.0.0",
    packages=find_packages(),
    install_requires=["aiohttp", "aiodns", "python-dotenv"],
    entry_points={"console_scripts": ["asm=asm.cli:main"]},
)
