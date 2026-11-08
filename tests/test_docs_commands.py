import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCS = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
FENCE = re.compile(r"^```(?P<info>[^\n]*)\n(?P<body>.*?)^```$", re.MULTILINE | re.DOTALL)
EXECUTABLE_LANGUAGES = {"sh", "bash", "shell", "python", "py"}
REFERENCE = re.compile(r"`([\w./-]+\.(?:py|md|yml|toml))((?:::[\w.]+)*)`")
SPAN = re.compile(r"`([^`\n]+)`")


def blocks():
    for path in DOCS:
        for match in FENCE.finditer(path.read_text()):
            info = match.group("info").split()
            yield path, (info[0] if info else ""), info[1:], match.group("body")


def tagged(kind):
    return [
        pytest.param(path, language, body, id=f"{path.name}:{index}")
        for index, (path, language, tags, body) in enumerate(blocks())
        if kind in tags
    ]


def test_every_executable_block_is_runnable_or_run_by_ci():
    for path, language, tags, body in blocks():
        if language in EXECUTABLE_LANGUAGES:
            assert set(tags) & {"runnable", "ci"}, f"{path.name}: untagged {language} block:\n{body}"


def test_docs_contain_runnable_blocks():
    assert tagged("runnable")
    assert tagged("ci")


@pytest.mark.parametrize(("path", "language", "body"), tagged("runnable"))
def test_runnable_block_runs(path, language, body):
    environment = {"PATH": os.path.dirname(sys.executable) + os.pathsep + os.environ["PATH"]}
    if language in {"python", "py"}:
        command = [sys.executable, "-I", "-c", body]
    else:
        command = ["sh", "-e", "-c", body]
    result = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(("path", "language", "body"), tagged("ci"))
def test_ci_block_lines_are_commands_the_workflow_runs(path, language, body):
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    run_lines = {line.split("run:", 1)[1].strip() for line in workflow.splitlines() if "run:" in line}
    for line in body.strip().splitlines():
        assert line.strip() in run_lines, f"{line!r} is not run by ci.yml"


def test_demo_runner_passes_every_scenario():
    environment = {"PATH": os.path.dirname(sys.executable) + os.pathsep + os.environ["PATH"]}
    result = subprocess.run(
        [sys.executable, "-m", "demo"], cwd=ROOT, env=environment, capture_output=True, text=True, timeout=300
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "11 of 11 scenarios passed" in result.stdout


def test_every_file_and_test_the_docs_cite_exists():
    cited = 0
    for path in DOCS:
        for match in REFERENCE.finditer(path.read_text()):
            file_part, names = match.groups()
            name = names.split("::")[-1] if names else None
            target = ROOT / file_part if "/" in file_part or (ROOT / file_part).exists() else ROOT / "docs" / file_part
            if file_part.startswith("docs/") or file_part in {"pyproject.toml"} or "/" in file_part:
                target = ROOT / file_part
            assert target.exists(), f"{path.name} cites missing file {file_part}"
            cited += 1
            if name:
                source = target.read_text()
                last = name.split(".")[-1]
                assert re.search(rf"(def|class) {re.escape(last)}\b", source), f"{path.name}: {file_part}::{name}"
    assert cited > 20


def test_every_test_citation_has_the_checked_form():
    for path in DOCS:
        for span in SPAN.findall(path.read_text()):
            if ".py::" in span:
                assert REFERENCE.fullmatch(f"`{span}`"), f"{path.name}: citation {span!r} is not checked"
