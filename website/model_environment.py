"""Small dependency-version contract shared by model training and inference."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version


RUNTIME_PACKAGE_NAMES = (
    "numpy",
    "scipy",
    "scikit-learn",
    "joblib",
    "threadpoolctl",
)


def package_versions(names: tuple[str, ...] = RUNTIME_PACKAGE_NAMES) -> dict[str, str]:
    return {name: version(name) for name in names}


def validate_runtime_package_versions(recorded: object) -> None:
    """Reject a new artifact when a required serving package has drifted."""
    if not isinstance(recorded, dict):
        raise ValueError("Content-model runtime package metadata is invalid")
    try:
        current = package_versions()
    except PackageNotFoundError as exc:
        raise ValueError("Content-model runtime dependency is missing") from exc
    for name, current_version in current.items():
        if recorded.get(name) != current_version:
            raise ValueError(f"Content-model {name} version is incompatible")
