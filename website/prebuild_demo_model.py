"""Prebuild the lightweight content-model cache for free deployments."""

from content_model import build_content_pipeline_from_env


if __name__ == "__main__":
    pipeline = build_content_pipeline_from_env(seed=42)
    metrics = pipeline["metrics"]
    print(
        "Demo content model ready: "
        f"model={metrics['model']} train={metrics['n_train']} test={metrics['n_test']}"
    )
