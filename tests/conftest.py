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
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

import boto3
import pytest
from botocore.exceptions import ClientError
from infrahouse_core.logging import setup_logging

LOG = logging.getLogger(__name__)
setup_logging(LOG, debug_botocore=False)

MODULE_VERSION = "1.0.1"

TERRAFORM_ROOT_DIR = "test_data"
CONNECTOR_ROOT = osp.join(TERRAFORM_ROOT_DIR, "connector")
VALIDATION_ROOT = osp.join(TERRAFORM_ROOT_DIR, "validation")
UPGRADE_ROOT = osp.join(TERRAFORM_ROOT_DIR, "upgrade")

TEST_ENVIRONMENT = "pytest"
RULE_NAME = f"loopproof-{TEST_ENVIRONMENT}-findings"
EXCLUDED_ACCOUNTS_PARAMETER = f"/loopproof/{TEST_ENVIRONMENT}/excluded-accounts"
# Part 1 of the install, which test_data/connector creates as the README tells a tenant to.
EXTERNAL_IDS_PARAMETER = f"/loopproof/{TEST_ENVIRONMENT}/external-ids"
REGISTRATION_TOKEN_PARAMETER = f"/loopproof/{TEST_ENVIRONMENT}/registration-token"
PARAMETER_ADDRESSES = [
    "aws_ssm_parameter.loopproof_external_ids",
    "aws_ssm_parameter.loopproof_registration_token",
]
# What Part 1 creates the parameters with, until the tenant fills them.
PLACEHOLDER = "unset"
REGISTRATION_ADDRESS = "module.connector.terraform_data.registration"
ROLE_ADDRESS = "module.connector.aws_iam_role.connector"
# JSON, which Terraform loads by itself and `terraform fmt` leaves alone.
TFVARS_FILE = "terraform.tfvars.json"
STATE_FILES = ["terraform.tfstate", "terraform.tfstate.backup"]
REGISTRATION_PATH = "/connector/registrations"
# For roots that plan only, which never call it.
UNCALLED_REGISTRATION_URL = "https://api.loopproof.invalid/connector/registrations"
SAMPLE_EVENT_PATH = osp.join(osp.dirname(__file__), "data", "findings-imported-v2.json")
# How many times the module's script calls the API before it gives up on a 5xx or a connection error.
REGISTRATION_ATTEMPTS = 4
# What the module's script says when the registration fails. Where a new registration token comes from,
# and whether LoopProof takes the role's ARN and Region pasted into its onboarding, depend on whether
# LoopProof has proven the tenant's account, which the script can't see, so it says both.
NEW_TOKEN_BEFORE_PROOF = (
    "Before LoopProof has proven your account, a new registration token comes from"
    " LoopProof's onboarding."
)
NEW_TOKEN_AFTER_PROOF = (
    "Once it has, an admin of your tenant mints one on LoopProof's Settings page."
    " A minted token registers only the role your tenant already has."
)
PASTE_BEFORE_PROOF = (
    "Before LoopProof has proven your account, you can paste the connector role ARN and"
    " the Region into LoopProof's onboarding instead:"
)
NO_PASTE_AFTER_PROOF = (
    "Once LoopProof has proven your account, it takes no paste: the registration needs a"
    " registration token and a machine that reaches LoopProof."
)

# A new or changed trust policy can take a minute or more to apply everywhere in IAM.
IAM_PROPAGATION_TIMEOUT = 300

# What the connector role may do: read findings and set their status and comment, read the excluded
# accounts, read repositories' tags and query the Config aggregators. Nothing more, and no write but the
# findings' status and comment.
CONNECTOR_ACTIONS = {
    "securityhub:GetFindings",
    "securityhub:BatchUpdateFindings",
    "ssm:GetParameter",
    "ecr:ListTagsForResource",
    "config:SelectAggregateResourceConfig",
}
# AWS Control Tower's AWS Config aggregator in the Audit account, which LoopProof queries by name. The
# connector root creates a stand-in of that name.
CONTROL_TOWER_AGGREGATOR = "aws-controltower-GuardrailsComplianceAggregator"
# A tag of the connector root's stand-in for a tenant's ECR repository.
REPOSITORY_TAG = {"Key": "team", "Value": "loopproof-pytest"}

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
    registration_url: str,
    excluded_accounts: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Build the variables of the ``connector`` test root module. The ExternalIds and the registration
    token aren't variables: the module reads them from the root's SSM parameters.

    :param aws_region: Region of the tenant side of the test.
    :param test_role_arn: Role that Terraform assumes, if any.
    :param registration_url: Where the module reports the role ARN.
    :param excluded_accounts: Accounts whose findings aren't forwarded; ``None`` for the module's default.
    :return: Variable names and values.
    """
    return {
        "region": aws_region,
        "role_arn": test_role_arn,
        "environment": TEST_ENVIRONMENT,
        "registration_url": registration_url,
        "excluded_accounts": excluded_accounts,
    }


def terraform(
    root: str, *args: str, env: Optional[Dict[str, str]] = None
) -> subprocess.CompletedProcess:
    """
    Run a Terraform command in a root module and capture what it prints.

    :param root: Path to the Terraform root module.
    :param args: Terraform subcommand and arguments.
    :param env: Environment for Terraform; the test's own when ``None``.
    :return: The finished process; it may have failed.
    """
    # Flags must precede positional arguments, such as a plan file.
    cmd = ["terraform", args[0], "-no-color", *args[1:]]
    LOG.info("Executing in %s: %s", root, " ".join(cmd))
    result = subprocess.run(
        cmd, cwd=root, capture_output=True, text=True, check=False, env=env
    )
    LOG.info("stdout:\n%s", result.stdout)
    if result.stderr:
        LOG.info("stderr:\n%s", result.stderr)
    return result


def terraform_check(root: str, *args: str, env: Optional[Dict[str, str]] = None) -> str:
    """
    Run a Terraform command that must succeed.

    :param root: Path to the Terraform root module.
    :param args: Terraform subcommand and arguments.
    :param env: Environment for Terraform; the test's own when ``None``.
    :return: Everything the command printed, stdout and stderr.
    :raise subprocess.CalledProcessError: If Terraform exits with non-zero.
    """
    result = terraform(root, *args, env=env)
    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, result.args, output=result.stdout, stderr=result.stderr
        )
    return result.stdout + result.stderr


def printed(result: subprocess.CompletedProcess) -> str:
    """
    :param result: A finished Terraform command.
    :return: Everything it printed, with whitespace runs joined, since Terraform wraps long messages.
    """
    return " ".join((result.stdout + result.stderr).split())


def fill_parameters(
    ssm_client: Any,
    external_ids: Optional[List[str]] = None,
    registration_token: Optional[str] = None,
) -> None:
    """
    Put values in Part 1's parameters, as a tenant does after the first apply. ``None`` leaves one as it is.

    :param ssm_client: Systems Manager in the tenant's Region.
    :param external_ids: The ExternalIds, stored as a JSON list.
    :param registration_token: The registration token.
    """
    values = {
        EXTERNAL_IDS_PARAMETER: (
            None if external_ids is None else json.dumps(external_ids)
        ),
        REGISTRATION_TOKEN_PARAMETER: registration_token,
    }
    for name, value in values.items():
        if value is not None:
            ssm_client.put_parameter(
                Name=name, Value=value, Type="SecureString", Overwrite=True
            )


def state_text(root: str) -> str:
    """
    :param root: Path to the Terraform root module.
    :return: The contents of its state files, those that exist.
    """
    text = ""
    for name in STATE_FILES:
        if osp.exists(osp.join(root, name)):
            with open(osp.join(root, name), encoding="utf-8") as fp:
                text += fp.read()
    return text


def path_without(command: str, directory: str) -> str:
    """
    Build a ``PATH`` on which ``command`` isn't found, and everything else still is: each directory that
    holds it is replaced by one in ``directory`` with links to all its other entries.

    :param command: The command to hide, such as ``curl``.
    :param directory: An empty directory for the replacements.
    :return: The new ``PATH``.
    """
    entries = []
    for index, entry in enumerate(os.environ["PATH"].split(os.pathsep)):
        if not osp.exists(osp.join(entry, command)):
            entries.append(entry)
            continue
        replacement = osp.join(directory, str(index))
        os.mkdir(replacement)
        for name in os.listdir(entry):
            if name != command:
                os.symlink(osp.join(entry, name), osp.join(replacement, name))
        entries.append(replacement)
    path = os.pathsep.join(entries)
    assert shutil.which(command, path=path) is None
    return path


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
    root: str,
    ssm_client: Any,
    external_ids: List[str],
    registration_token: str,
    destroy_after: bool,
) -> Iterator[Tuple[Dict[str, Any], str]]:
    """
    Install the connector the tidy way: apply Part 1's parameters alone, fill them, then plan and apply
    everything, capturing the output. Destroy it all afterwards.

    :param root: Path to the Terraform root module, with its variables file written.
    :param ssm_client: Systems Manager in the tenant's Region.
    :param external_ids: The ExternalIds to store.
    :param registration_token: The registration token to store.
    :param destroy_after: Destroy the resources when the context exits.
    :return: The outputs and everything the full plan and apply printed.
    """
    try:
        terraform_check(root, "init", "-input=false")
        targets = [f"-target={address}" for address in PARAMETER_ADDRESSES]
        terraform_check(root, "apply", "-input=false", "-auto-approve", *targets)
        fill_parameters(ssm_client, external_ids, registration_token)
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
            self.session(principal_role_arn, external_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "AccessDenied":
                return False
            raise
        return True

    def session(
        self, principal_role_arn: str, external_id: Optional[str]
    ) -> boto3.Session:
        """
        Assume the connector role.

        :param principal_role_arn: The stand-in control-plane role to call from.
        :param external_id: ExternalId to present, or None to present none.
        :return: Session as the connector role.
        :raise ClientError: If STS refuses.
        """
        return assumed_session(
            self._principal(principal_role_arn),
            self._connector_role_arn,
            self._region,
            external_id,
        )

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
    A stand-in for LoopProof's registration API, listening on 127.0.0.1. It records every request and
    answers each with the next of ``answers``, repeating the last: an HTTP status, or :data:`DROP` to
    close the connection without answering. 200 says ``{"status": "registered"}``, as LoopProof does;
    any other status says ``{"detail": <message>}``.
    """

    DROP = "drop"

    def __init__(self):
        self.requests: List[Dict[str, Any]] = []
        self.message = "registration token expired"
        self._answers: List[Any] = [200]
        self._lock = threading.Lock()
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

    def answer(self, *answers: Any) -> None:
        """
        Set the answers to the next requests; the last one repeats.

        :param answers: HTTP statuses, or :data:`DROP`.
        """
        with self._lock:
            self._answers = list(answers)

    def start(self) -> None:
        """Start serving in a background thread."""
        self._thread.start()

    def stop(self) -> None:
        """Stop serving and close the socket."""
        self._httpd.shutdown()
        self._httpd.server_close()

    # --- Private methods ---

    def _next_answer(self) -> Any:
        """
        :return: The answer to the request being handled.
        """
        with self._lock:
            return self._answers.pop(0) if len(self._answers) > 1 else self._answers[0]

    def _handler(self) -> type:
        """
        :return: A request handler class bound to this server.
        """
        server = self

        class Handler(BaseHTTPRequestHandler):
            """Records the request and answers with the server's next answer."""

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
                answer = server._next_answer()  # pylint: disable=protected-access
                if answer == RegistrationServer.DROP:
                    # curl reports an empty reply, error 52, which the module retries.
                    self.close_connection = True
                    return
                body = json.dumps(
                    {"status": "registered"}
                    if answer == 200
                    else {"detail": server.message}
                ).encode("utf-8")
                self.send_response(answer)
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


@pytest.fixture()
def events_client(boto3_session, aws_region):
    """EventBridge in the tenant's Region, where the module puts the rule."""
    return boto3_session.client("events", region_name=aws_region)


@pytest.fixture()
def ssm_client(boto3_session, aws_region):
    """Systems Manager in the tenant's Region, where the module puts the parameter."""
    return boto3_session.client("ssm", region_name=aws_region)


def finding_event(
    severity: str, activity: str = "Create", account_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Build a "Findings Imported V2" event from the sample in ``tests/data``.

    The envelope follows
    https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-cwe-event-formats.html,
    one finding per event at ``detail.findings[0]``. The finding is OCSF, as Security Hub sends it:
    https://schema.ocsf.io/1.6.0/classes/detection_finding.

    :param severity: OCSF severity caption, such as ``High``.
    :param activity: OCSF activity: ``Create``, ``Update`` or ``Close``.
    :param account_id: The finding's account, ``cloud.account.uid``; the sample's when ``None``.
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
    if account_id is not None:
        finding["cloud"]["account"]["uid"] = account_id
    return event


def forwarding_pattern_document(excluded_accounts: List[str]) -> Dict[str, Any]:
    """
    :param excluded_accounts: The excluded accounts, sorted.
    :return: The forwarding pattern the module should write for the default severities.
    """
    findings: Dict[str, Any] = {
        "severity_id": [OCSF_SEVERITY_IDS[s] for s in ["High", "Critical", "Fatal"]]
    }
    if excluded_accounts:
        findings["cloud"] = {"account": {"uid": [{"anything-but": excluded_accounts}]}}
    return {
        "source": ["aws.securityhub"],
        "detail-type": ["Findings Imported V2"],
        "detail": {"findings": findings},
    }


def forwarded(events_client: Any, event: Dict[str, Any]) -> bool:
    """
    :param events_client: EventBridge in the tenant's Region.
    :param event: A "Findings Imported V2" event.
    :return: Whether the forwarding rule's pattern, as EventBridge stores it, matches the event.
    """
    pattern = events_client.describe_rule(Name=RULE_NAME)["EventPattern"]
    return events_client.test_event_pattern(
        EventPattern=pattern, Event=json.dumps(event)
    )["Result"]


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


def inline_policy_statements(iam_client: Any, role_name: str) -> List[Dict[str, Any]]:
    """
    :param iam_client: IAM.
    :param role_name: A role with inline policies only.
    :return: The statements of all its inline policies.
    :raise AssertionError: If the role has a managed policy attached.
    """
    assert (
        iam_client.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
        == []
    )
    return [
        statement
        for name in iam_client.list_role_policies(RoleName=role_name)["PolicyNames"]
        for statement in policy_statements(
            iam_client.get_role_policy(RoleName=role_name, PolicyName=name)[
                "PolicyDocument"
            ]
        )
    ]


def allowed_actions(iam_client: Any, role_name: str) -> Set[str]:
    """
    :param iam_client: IAM.
    :param role_name: A role with inline policies only.
    :return: Every action its policies allow, as written.
    """
    return {
        action
        for statement in inline_policy_statements(iam_client, role_name)
        if statement["Effect"] == "Allow"
        for action in as_list(statement["Action"])
    }
