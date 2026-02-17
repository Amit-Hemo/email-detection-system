from pathlib import Path


def get_project_root() -> Path:
    """
    Get the root directory of the project.
    """
    current_file_path = Path(__file__).resolve()

    for parent in current_file_path.parents:
        if (parent / ".git").exists() or (parent / "pyproject.toml").exists():
            return parent

    raise ValueError("Project root not found")
