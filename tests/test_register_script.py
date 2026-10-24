"""
files/register.sh on its own, with a stand-in for curl first on PATH that records its arguments and
its standard input, and answers as told, and one for sleep that records the delays without waiting.
Creates nothing in AWS. The token must reach curl on standard input only, never as an argument, where
any user of the machine could read it in the process list, and the script must never print it.

The script can't tell whether LoopProof has proven the tenant's account, so every failure says what
to do both before and after: where a new registration token comes from, and that LoopProof takes the
role's ARN and Region pasted into its onboarding only before.
"""

import os
import stat
import subprocess
from os import path as osp
from textwrap import dedent
from typing import Dict, List

import pytest

from tests.conftest import (
    NEW_TOKEN_AFTER_PROOF,
    NEW_TOKEN_BEFORE_PROOF,
    NO_PASTE_AFTER_PROOF,
    PASTE_BEFORE_PROOF,
    REGISTRATION_ATTEMPTS,
    new_registration_token,
    path_without,
)

# The tests take aws_provider_version without using it: make test-clean selects tests by this id.
pytestmark = pytest.mark.parametrize("aws_provider_version", ["~> 6.0"], ids=["aws-6"])

SCRIPT = osp.join(osp.dirname(__file__), "..", "files", "register.sh")
ROLE_ARN = "arn:aws:iam::111122223333:role/loopproof-pytest-connector"
TOKEN_PARAMETER_ARN = (
    "arn:aws:ssm:us-west-2:111122223333:parameter/loopproof/pytest/registration-token"
)
BODY = f'{{"role_arn":"{ROLE_ARN}","region":"us-west-2"}}'

# Answers like curl -sS --fail-with-body: the body to --output, the HTTP version and status from
# --write-out, exit 22 on an HTTP error, for "drop" no answer, as curl reports an empty reply, and for
# "certificate" no answer either, as curl reports a certificate it doesn't trust.
FAKE_CURL = dedent("""\
    #!/bin/sh
    if [ "$1" = --version ]; then
        echo "curl ${FAKE_CURL_VERSION:-8.7.1} (stand-in) libcurl/${FAKE_CURL_VERSION:-8.7.1}"
        exit 0
    fi
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
    if [ "$answer" = certificate ]; then
        echo "curl: (60) SSL certificate problem: unable to get local issuer certificate" >&2
        printf '0 000'
        exit 60
    fi
    printf '{"detail": "the stand-in answered %s"}' "$answer" > "$output"
    printf '1.1 %s' "$answer"
    [ "$answer" -lt 400 ] || exit 22
    """)
FAKE_SLEEP = dedent("""\
    #!/bin/sh
    echo "$1" >> "$FAKE_CURL_DIR/sleeps"
    """)


def write_executable(file_path: str, content: str) -> None:
    """
    Write a stand-in command.

    :param file_path: Where to write it.
    :param content: The script.
    """
    with open(file_path, "w", encoding="utf-8") as fp:
        fp.write(content)
    os.chmod(file_path, os.stat(file_path).st_mode | stat.S_IXUSR)


def run_script(
    directory: str,
    token: str,
    answers: List[str],
    curl_version: str = "8.7.1",
    curl: bool = True,
) -> Dict[str, object]:
    """
    Run the script with the stand-ins for curl and sleep.

    :param directory: An empty directory for the stand-ins and their records.
    :param token: The registration token the script gets.
    :param answers: The stand-in's answers, one per call; the last repeats.
    :param curl_version: The version the stand-in reports.
    :param curl: Whether curl is on PATH at all; without it, neither the stand-in nor the real one is.
    :return: The script's exit code and output, each call's arguments and standard input, and the
        delays it slept.
    """
    write_executable(osp.join(directory, "sleep"), FAKE_SLEEP)
    path = os.environ["PATH"]
    if curl:
        write_executable(osp.join(directory, "curl"), FAKE_CURL)
    else:
        os.mkdir(osp.join(directory, "path"))
        path = path_without("curl", osp.join(directory, "path"))
    with open(osp.join(directory, "answers"), "w", encoding="utf-8") as fp:
        fp.write("\n".join(answers) + "\n")
    result = subprocess.run(
        ["/bin/sh", SCRIPT],
        env={
            **os.environ,
            "PATH": f"{directory}{os.pathsep}{path}",
            "FAKE_CURL_DIR": directory,
            "FAKE_CURL_VERSION": curl_version,
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
    sleeps = []
    if osp.exists(osp.join(directory, "sleeps")):
        with open(osp.join(directory, "sleeps"), encoding="utf-8") as fp:
            sleeps = fp.read().split()
    return {
        "returncode": result.returncode,
        "output": result.stdout + result.stderr,
        "calls": calls,
        "sleeps": sleeps,
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
    """
    A 4xx prints the status, LoopProof's answer, to get a new token and where it comes from, and what to
    paste instead before LoopProof has proven the account.
    """
    result = run_script(str(tmp_path), new_registration_token(), ["401"])
    output = " ".join(result["output"].split())

    assert "LoopProof refused the connector registration: HTTP/1.1 401" in output
    assert 'LoopProof\'s answer: {"detail": "the stand-in answered 401"}' in output
    assert (
        "Get a new registration token in LoopProof and put it in the SSM parameter"
        f" {TOKEN_PARAMETER_ARN}, then apply again."
        f" {NEW_TOKEN_BEFORE_PROOF} {NEW_TOKEN_AFTER_PROOF}"
        f" {PASTE_BEFORE_PROOF} Role ARN: {ROLE_ARN} Region: us-west-2"
        f" {NO_PASTE_AFTER_PROOF}" in output
    )


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


@pytest.mark.parametrize(
    "curl_version, calls",
    [("7.61.1", 0), ("7.75.0", 0), ("6.5.2", 0), ("7.76.0", 1), ("8.5.0", 1)],
    ids=["rhel-8", "7.75", "6.x", "7.76", "noble"],
)
def test_curl_version(
    aws_provider_version, tmp_path, curl_version, calls
):  # pylint: disable=unused-argument
    """A curl older than 7.76.0, which lacks --fail-with-body, fails before any call, saying so."""
    result = run_script(str(tmp_path), new_registration_token(), ["200"], curl_version)

    assert len(result["calls"]) == calls
    if calls:
        assert result["returncode"] == 0, result["output"]
    else:
        assert result["returncode"] == 1
        assert (
            "registers the connector role with curl 7.76.0 or later, and this machine has"
            f" curl {curl_version}." in " ".join(result["output"].split())
        )


# Every way the script fails: what makes it fail, how many calls it makes first, and whether the token
# is the problem, so that a new one helps.
FAILURES = [
    pytest.param({"answers": ["401"]}, 1, True, id="401"),
    pytest.param({"answers": ["409"]}, 1, True, id="409"),
    pytest.param({"answers": ["429"]}, 1, True, id="429"),
    pytest.param({"token": "unset"}, 0, True, id="placeholder"),
    pytest.param({"token": "lprt_with space"}, 0, True, id="whitespace"),
    pytest.param({"token": "tok_" + "x" * 32}, 0, True, id="wrong-prefix"),
    pytest.param(
        {"answers": ["500"]}, REGISTRATION_ATTEMPTS, False, id="500-every-time"
    ),
    pytest.param(
        {"answers": ["drop"]}, REGISTRATION_ATTEMPTS, False, id="drop-every-time"
    ),
    pytest.param({"answers": ["certificate"]}, 1, False, id="untrusted-certificate"),
    pytest.param({"answers": ["302"]}, 1, False, id="unexpected-status"),
    pytest.param({"curl_version": "7.61.1"}, 0, False, id="old-curl"),
    pytest.param({"curl": False}, 0, False, id="no-curl"),
]


def failed_run(directory: str, how: Dict[str, object]) -> Dict[str, object]:
    """
    Run the script so that it fails.

    :param directory: An empty directory for the stand-ins and their records.
    :param how: What makes it fail: ``token``, ``answers``, ``curl_version`` or ``curl``, as
        :func:`run_script` takes them; a new token and a 200 otherwise.
    :return: What :func:`run_script` returns, with the token it ran with.
    """
    token = how.get("token", new_registration_token())
    result = run_script(
        directory,
        token,
        how.get("answers", ["200"]),
        how.get("curl_version", "8.7.1"),
        curl=how.get("curl", True),
    )
    return {**result, "token": token}


@pytest.mark.parametrize("how, calls, token_problem", FAILURES)
def test_failure_keeps_exit_code_and_retries(
    aws_provider_version, tmp_path, how, calls, token_problem
):  # pylint: disable=unused-argument
    """
    Every failure exits 1, after as many calls as 1.0.0 made: none before the checks pass, one for a
    4xx or an answer it doesn't retry, four for a 5xx or a dropped connection, 2, 4 and 8 seconds
    apart. It never prints the token.
    """
    result = failed_run(str(tmp_path), how)

    assert result["returncode"] == 1, result["output"]
    assert len(result["calls"]) == calls
    if calls == REGISTRATION_ATTEMPTS:
        assert result["sleeps"] == ["2", "4", "8"]
    else:
        assert result["sleeps"] == []
    # The placeholder isn't a token, and the message names it.
    if result["token"] != "unset":
        assert result["token"] not in result["output"]


@pytest.mark.parametrize("how, calls, token_problem", FAILURES)
def test_new_token_from_both_places(
    aws_provider_version, tmp_path, how, calls, token_problem
):  # pylint: disable=unused-argument
    """
    A failure that a new token fixes says where one comes from, before LoopProof has proven the account
    and after; any other failure doesn't ask for a new token.
    """
    result = failed_run(str(tmp_path), how)
    output = " ".join(result["output"].split())

    if token_problem:
        assert f"{NEW_TOKEN_BEFORE_PROOF} {NEW_TOKEN_AFTER_PROOF}" in output
    else:
        assert "a new registration token" not in output.lower()
        assert "Settings page" not in output
    # Onboarding is named only in the sentences that say "before LoopProof has proven your account".
    assert output.count("LoopProof's onboarding") == (2 if token_problem else 1)


@pytest.mark.parametrize("how, calls, token_problem", FAILURES)
def test_paste_only_before_proof(
    aws_provider_version, tmp_path, how, calls, token_problem
):  # pylint: disable=unused-argument
    """
    Every failure offers the role's ARN and Region to paste, only before LoopProof has proven the
    account, and says what the registration needs after.
    """
    result = failed_run(str(tmp_path), how)
    output = " ".join(result["output"].split())

    assert (
        f"{PASTE_BEFORE_PROOF} Role ARN: {ROLE_ARN} Region: us-west-2"
        f" {NO_PASTE_AFTER_PROOF}" in output
    )
    # Those two sentences are the only ones that mention a paste.
    assert output.lower().count("paste") == 2
