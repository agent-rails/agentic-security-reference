import re
import subprocess
import sys
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parent.parent
LIBRARY_PINS = {"agent-warrant==0.1.0", "toolcall-authz==0.3.0"}


def test_library_dependencies_are_pinned_to_exact_releases():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    libraries = [d for d in project["dependencies"] if d.startswith(("agent-warrant", "toolcall-authz", "agent-guard"))]
    assert sorted(libraries) == sorted(LIBRARY_PINS)


def test_installed_library_versions_match_the_pins():
    from importlib.metadata import version

    assert {f"{name}=={version(name)}" for name in ("agent-warrant", "toolcall-authz")} == LIBRARY_PINS


def test_workflow_actions_are_pinned_to_commit_shas():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    uses = re.findall(r"uses:\s*(\S+)", workflow)
    assert uses
    for reference in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", reference), reference


def test_workflow_token_is_read_only_and_credentials_are_not_persisted():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert re.search(r"^permissions:\n  contents: read$", workflow, re.MULTILINE)
    assert "persist-credentials: false" in workflow


def test_libraries_import():
    import agent_guard  # noqa: F401
    import agent_warrant  # noqa: F401
    import agentguard_identity  # noqa: F401


def test_agent_guard_core_does_not_import_agent_warrant():
    code = (
        "import sys, agent_guard, agentguard_identity.credentials;sys.exit(1 if 'agent_warrant' in sys.modules else 0)"
    )
    result = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr


def test_ci_runs_the_separate_user_test_as_a_second_os_user():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "useradd" in workflow
    assert "ASR_AGENT_USER: asr-agent" in workflow
    assert "ASR_AGENT_GROUP: asr-agents" in workflow
    assert "tests/test_separate_user.py" in workflow


def test_type_check_is_strict_and_runs_in_ci():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["mypy"]
    assert config["strict"] is True
    assert "executor" in config["files"]
    assert "- run: mypy" in (ROOT / ".github" / "workflows" / "ci.yml").read_text()


def locked_versions():
    versions = {}
    for line in (ROOT / "requirements-ci.txt").read_text().splitlines():
        if not line or line[0] in " #-":
            continue
        name, version = line.split(";")[0].split()[0].split("==")
        versions[canonicalize_name(name)] = version
    return versions


def test_lock_pins_every_requirement_with_hashes():
    text = (ROOT / "requirements-ci.txt").read_text()
    entries = re.split(r"\n(?=\S)", text.strip())
    assert entries
    for entry in entries:
        assert re.match(r"[\w.-]+==[\w.]+", entry), entry
        hash_lines = [line for line in entry.splitlines()[1:] if not line.lstrip().startswith("#")]
        assert any(re.fullmatch(r"\s+--hash=sha256:[0-9a-f]{64}( \\)?", line) for line in hash_lines), entry


def test_lock_satisfies_pyproject_and_build_requirements():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    required = [
        *data["project"]["dependencies"],
        *data["project"]["optional-dependencies"]["dev"],
        *data["build-system"]["requires"],
    ]
    versions = locked_versions()
    for text in required:
        requirement = Requirement(text)
        name = canonicalize_name(requirement.name)
        assert name in versions, text
        assert requirement.specifier.contains(versions[name], prereleases=True), (text, versions[name])
    assert {f"{name}=={versions[name]}" for name in ("agent-warrant", "toolcall-authz")} == LIBRARY_PINS


INSTALLER = re.compile(r"\b(pip3?|uv|pipx|poetry|conda|easy_install)\b")


def test_ci_installs_only_from_the_hash_lock():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    installs = [line.strip().removeprefix("- run:").strip() for line in workflow.splitlines() if INSTALLER.search(line)]
    assert installs == [
        "python -m pip install --require-hashes -r requirements-ci.txt",
        "python -m pip install --no-deps --no-build-isolation -e .",
        "python -m pip check",
    ]
