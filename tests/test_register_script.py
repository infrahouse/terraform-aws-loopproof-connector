"""
files/register.sh on its own, with a stand-in for curl first on PATH that records its arguments and
its standard input, and answers as told. Creates nothing in AWS. The token must reach curl on standard
input only, never as an argument, where any user of the machine could read it in the process list,
and the script must never print it.
"""

import os
import stat
import subprocess
from os import path as osp
from textwrap import dedent
from typing import Dict, List

import pytest

from tests.conftest import REGISTRATION_ATTEMPTS, new_registration_token

# The tests take aws_provider_version without using it: make test-clean selects tests by this id.
pytestmark = pytest.mark.parametrize("aws_provider_version", ["~> 6.0"], ids=["aws-6"])

SCRIPT = osp.join(osp.dirname(__file__), "..", "files", "register.sh")
ROLE_ARN = "arn:aws:iam::111122223333:role/loopproof-pytest-connector"
TOKEN_PARAMETER_ARN = (
    "arn:aws:ssm:us-west-2:111122223333:parameter/loopproof/pytest/registration-token"
)
BODY = f'{{"role_arn":"{ROLE_ARN}","region":"us-west-2"}}'

# Answers like curl -sS --fail-with-body: the body to --output, the HTTP version and status from
# --write-out, exit 22 on an HTTP error, and for "drop" no answer, as curl reports an empty reply.
FAKE_CURL = dedent("""\
    #!/bin/sh
    n=$(($(cat "$FAKE_CURL_DIR/calls" 2> /dev/null || echo 0) + 1))
    echo "$n" > "$FAKE_CURL_DIR/calls"
    for argument in "$@"; do printf '%s\\n' "$argument"; done > "$FAKE_CURL_DIR/argv.$n"
    cat > "$FAKE_CURL_DIR/stdin.$n"
    output=
    while [ $# -gt 0 ]; do
        [ "$1" = --output ] && output=$2
        shift
    done
    answer=$(sed -n "${n}p" "$FAKE_CURL_DIR/answers")
    [ -n "$answer" ] || answer=$(tail -n 1 "$FAKE_CURL_DIR/answers")
    if [ "$answer" = drop ]; then
        echo "curl: (52) Empty reply from server" >&2
        printf '0 000'
        exit 52
    fi
    printf '{"detail": "the stand-in answered %s"}' "$answer" > "$output"
    printf '1.1 %s' "$answer"
    [ "$answer" -lt 400 ] || exit 22
    """)


def run_script(directory: str, token: str, answers: List[str]) -> Dict[str, object]:
    """
    Run the script with the stand-in curl.

    :param directory: An empty directory for the stand-in and its records.
    :param token: The registration token the script gets.
    :param answers: The stand-in's answers, one per call; the last repeats.
    :return: The script's exit code and output, and each call's arguments and standard input.
    """
    curl = osp.join(directory, "curl")
    with open(curl, "w", encoding="utf-8") as fp:
        fp.write(FAKE_CURL)
    os.chmod(curl, os.stat(curl).st_mode | stat.S_IXUSR)
    with open(osp.join(directory, "answers"), "w", encoding="utf-8") as fp:
        fp.write("\n".join(answers) + "\n")
    result = subprocess.run(
        ["/bin/sh", SCRIPT],
        env={
            **os.environ,
            "PATH": f"{directory}{os.pathsep}{os.environ['PATH']}",
            "FAKE_CURL_DIR": directory,
            "LOOPPROOF_REGISTRATION_TOKEN": token,
            "LOOPPROOF_REGISTRATION_URL": "https://api.loopproof.invalid/connector/registrations",
            "LOOPPROOF_REGISTRATION_BODY": BODY,
            "LOOPPROOF_TOKEN_PARAMETER_ARN": TOKEN_PARAMETER_ARN,
            "LOOPPROOF_ROLE_ARN": ROLE_ARN,
            "LOOPPROOF_REGION": "us-west-2",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    calls = []
    count = 0
    if osp.exists(osp.join(directory, "calls")):
        with open(osp.join(directory, "calls"), encoding="utf-8") as fp:
            count = int(fp.read())
    for n in range(1, count + 1):
        with open(osp.join(directory, f"argv.{n}"), encoding="utf-8") as fp:
            argv = fp.read().splitlines()
        with open(osp.join(directory, f"stdin.{n}"), encoding="utf-8") as fp:
            stdin = fp.read()
        calls.append({"argv": argv, "stdin": stdin})
    return {
        "returncode": result.returncode,
        "output": result.stdout + result.stderr,
        "calls": calls,
    }


@pytest.mark.parametrize(
    "answers, returncode, calls",
    [
        (["200"], 0, 1),
        (["401"], 1, 1),
        (["408"], 1, 1),
        (["429"], 1, 1),
        (["409"], 1, 1),
        (["503", "200"], 0, 2),
        (["drop", "200"], 0, 2),
        (["500"], 1, REGISTRATION_ATTEMPTS),
        (["drop"], 1, REGISTRATION_ATTEMPTS),
    ],
    ids=[
        "200",
        "401",
        "408",
        "429",
        "409",
        "503-then-200",
        "drop-then-200",
        "500-every-time",
        "drop-every-time",
    ],
)
def test_token_on_stdin_only(
    aws_provider_version, tmp_path, answers, returncode, calls
):  # pylint: disable=unused-argument
    """
    Each call carries the token in an Authorization header read from standard input, never as an
    argument; 4xx answers aren't retried, 5xx answers and dropped connections are; the script never
    prints the token.
    """
    token = new_registration_token()
    result = run_script(str(tmp_path), token, answers)

    assert result["returncode"] == returncode, result["output"]
    assert len(result["calls"]) == calls
    for call in result["calls"]:
        assert call["stdin"] == f"Authorization: Bearer {token}\n"
        assert not [argument for argument in call["argv"] if token in argument]
        # The header comes from standard input; the body and the URL are arguments.
        assert "@-" in call["argv"]
        assert BODY in call["argv"]
        for flag in ["-sS", "--fail-with-body", "--max-time"]:
            assert flag in call["argv"]
    assert token not in result["output"]


def test_refusal_message(
    aws_provider_version, tmp_path
):  # pylint: disable=unused-argument
    """A 4xx prints the status, LoopProof's answer, what to do and what to paste instead."""
    result = run_script(str(tmp_path), new_registration_token(), ["401"])
    output = " ".join(result["output"].split())

    assert "LoopProof refused the connector registration: HTTP/1.1 401" in output
    assert 'LoopProof\'s answer: {"detail": "the stand-in answered 401"}' in output
    assert (
        "Get a new registration token in LoopProof and put it in the SSM parameter"
        f" {TOKEN_PARAMETER_ARN}, then apply again." in output
    )
    assert f"Role ARN: {ROLE_ARN}" in output
    assert "Region: us-west-2" in output


@pytest.mark.parametrize(
    "token, message, echo",
    [
        ("unset", "still holds the placeholder", None),
        # The message itself names the prefix.
        ("lprt_", "doesn't hold a registration token", None),
        ("lprt_with space", "doesn't hold a registration token", "lprt_with space"),
        ("tok_" + "x" * 32, "doesn't hold a registration token", "tok_"),
    ],
    ids=["placeholder", "prefix-only", "whitespace", "wrong-prefix"],
)
def test_not_a_token(
    aws_provider_version, tmp_path, token, message, echo
):  # pylint: disable=unused-argument
    """A parameter that doesn't hold a token fails before any call, naming the parameter, not the value."""
    result = run_script(str(tmp_path), token, ["200"])

    assert result["returncode"] == 1
    assert result["calls"] == []
    assert f"The SSM parameter {TOKEN_PARAMETER_ARN} {message}" in " ".join(
        result["output"].split()
    )
    if echo is not None:
        assert echo not in result["output"]
