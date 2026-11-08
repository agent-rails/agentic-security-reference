import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SHA = re.compile(r"@[0-9a-f]{40}$")


def test_library_dependencies_are_pinned_to_commit_shas():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    libraries = [d for d in project["dependencies"] if d.startswith(("agent-warrant", "toolcall-authz"))]
    assert len(libraries) == 2
    for dependency in libraries:
        assert SHA.search(dependency), dependency


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
