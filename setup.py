from setuptools import find_packages, setup

setup(
    packages=find_packages(include=["djangoapi_guard", "djangoapi_guard.*"]),
    include_package_data=True,
    package_data={
        "djangoapi_guard": ["py.typed"],
    },
)
