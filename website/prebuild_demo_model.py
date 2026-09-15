"""Train and write a verified content-model artifact outside the web process."""

import argparse
from pathlib import Path

from content_model import (
    build_content_pipeline_from_env,
    save_content_pipeline_artifact,
)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent.parent
        / "phishing-detection" / "data" / "content_model_artifact.pkl",
        help="Destination for the versioned model artifact",
    )
    args = parser.parse_args()
    pipeline = build_content_pipeline_from_env(seed=42)
    digest = save_content_pipeline_artifact(pipeline, args.output)
    metrics = pipeline["metrics"]
    print(
        "Offline content model ready: "
        f"model={metrics['model']} train={metrics['n_train']} test={metrics['n_test']}"
    )
    print(f"Artifact: {args.output.resolve()}")
    print(f"CONTENT_MODEL_ARTIFACT_SHA256={digest}")
