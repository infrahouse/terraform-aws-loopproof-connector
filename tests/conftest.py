"""
Shared helpers and fixtures for the LoopProof connector tests.

In the tests the "control plane" is the test account itself: a probe role named
``loopproof-<environment>-probe`` stands in for LoopProof's roles, and an event bus in
``us-west-1`` stands in for the control-plane bus.
"""

import json
import logging
import os
import secrets
import shutil
import subprocess
import threading
import time
from contextlib import contextmanager
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from os import path as osp
from textwrap import dedent
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

import boto3
import pytest
from botocore.exceptions import ClientError
from infrahouse_core.logging import setup_logging

LOG = logging.getLogger(__name__)
setup_logging(LOG, debug_botocore=False)

MODULE_VERSION = "0.0.0"

TERRAFORM_ROOT_DIR = "test_data"
CONNECTOR_ROOT = osp.join(TERRAFORM_ROOT_DIR, "connector")
VALIDATION_ROOT = osp.join(TERRAFORM_ROOT_DIR, "validation")

TEST_ENVIRONMENT = "pytest"
# JSON, which Terraform loads by itself and `terraform fmt` leaves alone.
TFVARS_FILE = "terraform.tfvars.json"
REGISTRATION_PATH = "/connector/registrations"
SAMPLE_EVENT_PATH = osp.join(osp.dirname(__file__), "data", "findings-imported-v2.json")

# A new or changed trust policy can take a minute or more to apply everywhere in IAM.
IAM_PROPAGATION_TIMEOUT = 300

# OCSF enums, from https://schema.ocsf.io/1.6.0/classes/detection_finding.
# Kept apart from the module's own table so the tests check the module's mapping.
OCSF_SEVERITY_IDS = {
    "Unknown": 0,
    "Informational": 1,
    "Low": 2,
    "Medium": 3,
    "High": 4,
    "Critical": 5,
    "Fatal": 6,
    "Other": 99,
}
OCSF_ACTIVITY_IDS = {"Create": 1, "Update": 2, "Close": 3}


def new_external_id() -> str:
    """
    Generate an ExternalId in LoopProof's format: 43 characters of ``[A-Za-z0-9_-]``.

    :return: A random ExternalId.
    """
    return secrets.token_urlsafe(32)


def new_registration_token() -> str:
    """
    Generate a registration token in LoopProof's format.

    :return: A random ``lprt_`` token.
    """
    return f"lprt_{secrets.token_urlsafe(24)}"


def write_terraform_tf(root: str, aws_provider_version: str) -> None:
    """
    Pin the AWS provider version of a test root module, and drop the previous provider install.

    :param root: Path to the Terraform root module.
    :param aws_provider_version: AWS provider version constraint, such as ``~> 6.0``.
    """
    shutil.rmtree(osp.join(root, ".terraform"), ignore_errors=True)
    lock_file = osp.join(root, ".terraform.lock.hcl")
    if osp.exists(lock_file):
        os.remove(lock_file)

    with open(osp.join(root, "terraform.tf"), "w", encoding="utf-8") as fp:
        fp.write(dedent(f"""\
            terraform {{
              required_providers {{
                aws = {{
                  source  = "hashicorp/aws"
                  version = "{aws_provider_version}"
                }}
              }}
            }}
            """))


def write_tfvars(root: str, values: Dict[str, Any]) -> None:
    """
    Write the variables file of a test root module.

    :param root: Path to the Terraform root module.
    :param values: Variable names and values; ``None`` becomes ``null``.
    """
    with open(osp.join(root, TFVARS_FILE), "w", encoding="utf-8") as fp:
        json.dump(values, fp, indent=2)
        fp.write("\n")


def connector_tfvars(
    aws_region: str,
    test_role_arn: Optional[str],
    external_ids: List[str],
    registration_url: str,
    registration_token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build the variables of the ``connector`` test root module.

    :param aws_region: Region of the tenant side of the test.
    :param test_role_arn: Role that Terraform assumes, if any.
    :param external_ids: ExternalIds for the connector role.
    :param registration_url: Where the module reports the role ARN.
    :param registration_token: Registration token; ``None`` disables the call.
    :return: Variable names and values.
    """
    return {
        "region": aws_region,
        "role_arn": test_role_arn,
        "environment": TEST_ENVIRONMENT,
        "external_ids": external_ids,
        "registration_url": registration_url,
        "registration_token": registration_token,
    }


def terraform(root: str, *args: str) -> subprocess.CompletedProcess:
    """
    Run a Terraform command in a root module and capture what it prints.

    :param root: Path to the Terraform root module.
    :param args: Terraform subcommand and arguments.
    :return: The finished process; it may have failed.
    """
    # Flags must precede positional arguments, such as a plan file.
    cmd = ["terraform", args[0], "-no-color", *args[1:]]
    LOG.info("Executing in %s: %s", root, " ".join(cmd))
    result = subprocess.run(cmd, cwd=root, capture_output=True, text=True, check=False)
    LOG.info("stdout:\n%s", result.stdout)
    if result.stderr:
        LOG.info("stderr:\n%s", result.stderr)
    return result


def terraform_check(root: str, *args: str) -> str:
    """
    Run a Terraform command that must succeed.

    :param root: Path to the Terraform root module.
    :param args: Terraform subcommand and arguments.
    :return: Everything the command printed, stdout and stderr.
    :raise subprocess.CalledProcessError: If Terraform exits with non-zero.
    """
    result = terraform(root, *args)
    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, result.args, output=result.stdout, stderr=result.stderr
        )
    return result.stdout + result.stderr


def terraform_outputs(root: str) -> Dict[str, Any]:
    """
    Read the root module's outputs.

    :param root: Path to the Terraform root module.
    :return: Output names and values.
    """
    raw = terraform_check(root, "output", "-json")
    return {name: output["value"] for name, output in json.loads(raw).items()}


@contextmanager
def connector_applied(
    root: str, destroy_after: bool
) -> Iterator[Tuple[Dict[str, Any], str]]:
    """
    Plan and apply a root module, capturing the output, and destroy it afterwards.

    :param root: Path to the Terraform root module, with its variables file written.
    :param destroy_after: Destroy the resources when the context exits.
    :return: The outputs and everything plan and apply printed.
    """
    try:
        terraform_check(root, "init", "-input=false")
        log = terraform_check(root, "plan", "-input=false", "-out=tfplan")
        log += terraform_check(root, "apply", "-input=false", "tfplan")
        yield terraform_outputs(root), log
    finally:
        if destroy_after:
            terraform_check(root, "destroy", "-input=false", "-auto-approve")


def assumed_session(
    session: boto3.Session,
    role_arn: str,
    region: str,
    external_id: Optional[str] = None,
) -> boto3.Session:
    """
    Assume a role and return a session with its credentials.

    :param session: Session to call STS with.
    :param role_arn: Role to assume.
    :param region: Region for the new session and STS endpoint.
    :param external_id: ExternalId to present, if any.
    :return: Session as the assumed role.
    :raise ClientError: If STS refuses.
    """
    kwargs = {"RoleArn": role_arn, "RoleSessionName": "pytest-loopproof-connector"}
    if external_id is not None:
        kwargs["ExternalId"] = external_id
    credentials = session.client("sts", region_name=region).assume_role(**kwargs)[
        "Credentials"
    ]
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region,
    )


def wait_for(
    condition: Callable[[], bool],
    description: str,
    timeout: int = IAM_PROPAGATION_TIMEOUT,
) -> None:
    """
    Poll a condition with exponential backoff until it holds.

    :param condition: Returns True when the wait is over. It may raise to fail at once.
    :param description: What is awaited, for the log and the error.
    :param timeout: Seconds to wait before giving up.
    :raise AssertionError: If the condition doesn't hold within the timeout.
    """
    deadline = time.time() + timeout
    delay = 2
    while not condition():
        if time.time() + delay > deadline:
            raise AssertionError(
                f"Timed out after {timeout}s waiting until {description}"
            )
        LOG.info("Waiting until %s; checking again in %ds", description, delay)
        time.sleep(delay)
        delay = min(delay * 2, 30)


def wait_until_settled(
    check: Callable[[], bool],
    description: str,
    settle_seconds: int,
    timeout: int,
    interval: int = 5,
) -> None:
    """
    Poll until a check has passed on every poll for ``settle_seconds`` in a row.

    Right after a trust policy change, some STS hosts keep using the previous policy for minutes,
    so a single success doesn't mean the change is in effect everywhere. A failed poll restarts
    the count.

    :param check: Returns True when the awaited state holds. It may raise to fail at once.
    :param description: What is awaited, for the log and the error.
    :param settle_seconds: How long the check must keep passing.
    :param timeout: Seconds to wait in total before giving up.
    :param interval: Seconds between polls.
    :raise AssertionError: If the check doesn't settle within the timeout.
    """
    deadline = time.time() + timeout
    passing_since: Optional[float] = None
    while True:
        now = time.time()
        if check():
            if passing_since is None:
                LOG.info(
                    "Now %s; waiting %ds for it to settle", description, settle_seconds
                )
                passing_since = now
            if now - passing_since >= settle_seconds:
                return
        elif passing_since is not None:
            LOG.info(
                "No longer %s after %ds; starting over",
                description,
                now - passing_since,
            )
            passing_since = None
        if now + interval > deadline:
            raise AssertionError(
                f"Timed out after {timeout}s waiting until {description} for {settle_seconds}s"
            )
        time.sleep(interval)


class ConnectorProbe:
    """
    Assumes the connector role the way LoopProof does: first a stand-in control-plane role,
    then the connector role from it.
    """

    def __init__(
        self, boto3_session: boto3.Session, region: str, connector_role_arn: str
    ):
        self._boto3_session = boto3_session
        self._region = region
        self._connector_role_arn = connector_role_arn
        self._principals: Dict[str, boto3.Session] = {}

    # --- Public methods ---

    def can_assume(self, principal_role_arn: str, external_id: Optional[str]) -> bool:
        """
        Try to assume the connector role.

        :param principal_role_arn: The stand-in control-plane role to call from.
        :param external_id: ExternalId to present, or None to present none.
        :return: True if STS allowed it, False if it answered AccessDenied.
        :raise ClientError: On any other STS error.
        """
        try:
            assumed_session(
                self._principal(principal_role_arn),
                self._connector_role_arn,
                self._region,
                external_id,
            )
        except ClientError as err:
            if err.response["Error"]["Code"] == "AccessDenied":
                return False
            raise
        return True

    # --- Private methods ---

    def _principal(self, role_arn: str) -> boto3.Session:
        """
        Return a session as a stand-in control-plane role, waiting until IAM lets the test role assume it.

        :param role_arn: The stand-in role.
        :return: Session as that role.
        """
        if role_arn not in self._principals:
            sessions: List[boto3.Session] = []

            def assumed() -> bool:
                try:
                    sessions.append(
                        assumed_session(self._boto3_session, role_arn, self._region)
                    )
                except ClientError as err:
                    if err.response["Error"]["Code"] == "AccessDenied":
                        return False
                    raise
                return True

            wait_for(assumed, f"the test role can assume {role_arn}")
            self._principals[role_arn] = sessions[-1]
        return self._principals[role_arn]


class RegistrationServer:
    """
    A stand-in for LoopProof's registration API, listening on 127.0.0.1.
    It records every request and answers with ``status``.
    """

    def __init__(self):
        self.requests: List[Dict[str, Any]] = []
        self.status = 200
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    # --- Public properties ---

    @property
    def url(self) -> str:
        """
        :return: The registration URL to give the module.
        """
        return f"http://127.0.0.1:{self._httpd.server_address[1]}{REGISTRATION_PATH}"

    # --- Public methods ---

    def start(self) -> None:
        """Start serving in a background thread."""
        self._thread.start()

    def stop(self) -> None:
        """Stop serving and close the socket."""
        self._httpd.shutdown()
        self._httpd.server_close()

    # --- Private methods ---

    def _handler(self) -> type:
        """
        :return: A request handler class bound to this server.
        """
        server = self

        class Handler(BaseHTTPRequestHandler):
            """Records the request and answers with the server's status."""

            def do_POST(self) -> None:  # pylint: disable=invalid-name
                length = int(self.headers.get("Content-Length", 0))
                server.requests.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "headers": dict(self.headers.items()),
                        "body": self.rfile.read(length).decode("utf-8"),
                    }
                )
                body = (
                    b'{"status": "ok"}'
                    if server.status == 200
                    else b'{"error": "rejected"}'
                )
                self.send_response(server.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # pylint: disable=invalid-name
                self.do_POST()

            def log_message(
                self, format: str, *args: Any
            ) -> None:  # pylint: disable=redefined-builtin
                LOG.info("Registration server: %s", format % args)

        return Handler


@contextmanager
def registration_server_running() -> Iterator[RegistrationServer]:
    """
    Run a :class:`RegistrationServer` for the duration of the context.

    :return: The running server.
    """
    server = RegistrationServer()
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture()
def registration_server() -> Iterator[RegistrationServer]:
    """A stand-in for LoopProof's registration API for one test."""
    with registration_server_running() as server:
        yield server


def finding_event(severity: str, activity: str = "Create") -> Dict[str, Any]:
    """
    Build a "Findings Imported V2" event from the sample in ``tests/data``.

    The envelope follows
    https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-cwe-event-formats.html,
    one finding per event at ``detail.findings[0]``. The finding is OCSF, as Security Hub sends it:
    https://schema.ocsf.io/1.6.0/classes/detection_finding.

    :param severity: OCSF severity caption, such as ``High``.
    :param activity: OCSF activity: ``Create``, ``Update`` or ``Close``.
    :return: The event.
    """
    with open(SAMPLE_EVENT_PATH, encoding="utf-8") as fp:
        event = json.load(fp)
    event = deepcopy(event)
    finding = event["detail"]["findings"][0]
    finding["severity"] = severity
    finding["severity_id"] = OCSF_SEVERITY_IDS[severity]
    finding["activity_id"] = OCSF_ACTIVITY_IDS[activity]
    finding["activity_name"] = activity
    finding["type_uid"] = finding["class_uid"] * 100 + finding["activity_id"]
    finding["type_name"] = f"{finding['class_name']}: {activity}"
    if activity == "Close":
        finding["status"] = "Resolved"
        finding["status_id"] = 4
    return event


def policy_statements(document: Any) -> List[Dict[str, Any]]:
    """
    Normalize an IAM policy document to its list of statements.

    :param document: Policy as boto3 returns it: a dict or a URL-encoded JSON string.
    :return: The statements.
    """
    if isinstance(document, str):
        document = json.loads(document)
    statements = document["Statement"]
    return statements if isinstance(statements, list) else [statements]


def as_list(value: Any) -> List[Any]:
    """
    :param value: A policy element that may be a scalar or a list.
    :return: The element as a list.
    """
    return value if isinstance(value, list) else [value]
