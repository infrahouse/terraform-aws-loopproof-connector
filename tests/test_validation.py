"""
Input validation. Each case plans the module with one bad value, either an input or the contents of
the ExternalIds parameter; nothing is created but the two parameters the module reads, which the
tests create and delete themselves.
"""

import json
from copy import deepcopy
from typing import Any, Dict, Iterator, List, Optional

import pytest

from tests.conftest import (
    EXCEPTION_RULE,
    PLACEHOLDER,
    THREAT_RULE,
    VALIDATION_ROOT,
    new_external_id,
    new_registration_token,
    printed,
    published_rule,
    terraform,
    terraform_check,
    terraform_json,
    VULN_CVE_RULE,
    VULN_PACKAGE_RULE,
    write_terraform_tf,
    write_tfvars,
)

CONTROL_PLANE_ACCOUNT_ID = "123456789012"
EVENT_BUS_ARN = f"arn:aws:events:us-west-1:{CONTROL_PLANE_ACCOUNT_ID}:event-bus/loopproof-pytest-findings"
# Apart from the connector root's, which test_data/connector creates.
EXTERNAL_IDS_PARAMETER = "/loopproof/pytest-validation/external-ids"
REGISTRATION_TOKEN_PARAMETER = "/loopproof/pytest-validation/registration-token"
EXTERNAL_ID = new_external_id()
OTHER_EXTERNAL_ID = new_external_id()
BAD_EXTERNAL_ID = EXTERNAL_ID[:-1] + "!"
ARN_MESSAGE = "must be the ARN of an SSM parameter"
SHAPE_MESSAGE = "must hold a JSON list of one ExternalId, or two during a rotation"

CASES = [
    (
        "account-id-short",
        {"control_plane_account_id": "12345"},
        "must be a 12-digit AWS account ID",
        None,
    ),
    (
        "account-id-letters",
        {"control_plane_account_id": "12345678901a"},
        "must be a 12-digit AWS account ID",
        None,
    ),
    # Terraform prints a string input's value beside the failed check, as for any input that isn't
    # sensitive, so these cases check the message only; the module's message doesn't repeat the value.
    (
        "external-ids-arn-a-name",
        {"external_ids_parameter_arn": "/loopproof/pytest/external-ids"},
        f"external_ids_parameter_arn {ARN_MESSAGE}",
        None,
    ),
    (
        "external-ids-arn-secret",
        {
            "external_ids_parameter_arn": "arn:aws:secretsmanager:us-west-2:123456789012:secret:loopproof-abcdef"
        },
        f"external_ids_parameter_arn {ARN_MESSAGE}",
        None,
    ),
    (
        "token-arn-a-document",
        {
            "registration_token_parameter_arn": "arn:aws:ssm:us-west-2:123456789012:document/loopproof"
        },
        f"registration_token_parameter_arn {ARN_MESSAGE}",
        None,
    ),
    (
        "token-arn-empty",
        {"registration_token_parameter_arn": ""},
        f"registration_token_parameter_arn {ARN_MESSAGE}",
        None,
    ),
    (
        "url-http",
        {"registration_url": "http://api.staging.loopproof.ai/connector/registrations"},
        "registration_url must be an https:// URL",
        None,
    ),
    (
        "url-http-localhost-lookalike",
        {"registration_url": "http://localhost.example.com/connector/registrations"},
        "registration_url must be an https:// URL",
        None,
    ),
    (
        "url-credentials",
        {
            "registration_url": "https://user:secret@api.staging.loopproof.ai/connector/registrations"
        },
        "registration_url must be an https:// URL",
        None,
    ),
    (
        "environment-uppercase",
        {"environment": "Staging"},
        "lowercase letters, digits or hyphens",
        None,
    ),
    (
        "event-bus-not-a-bus",
        {
            "event_bus_arn": f"arn:aws:sqs:us-west-1:{CONTROL_PLANE_ACCOUNT_ID}:loopproof"
        },
        "event_bus_arn must be an EventBridge event bus ARN",
        None,
    ),
    (
        "event-bus-other-account",
        {
            "event_bus_arn": "arn:aws:events:us-west-1:210987654321:event-bus/loopproof-pytest-findings"
        },
        f"must be a bus in the control-plane account {CONTROL_PLANE_ACCOUNT_ID}",
        None,
    ),
    (
        "severity-asff-label",
        {"severities": ["HIGH"]},
        "severities may only contain",
        None,
    ),
    (
        "severity-unknown-word",
        {"severities": ["High", "Severe"]},
        "severities may only contain",
        None,
    ),
    ("severities-empty", {"severities": []}, "must list at least one severity", None),
    # The messages name the input without echoing the bad value.
    (
        "excluded-account-short",
        {"excluded_accounts": ["98765432101"]},
        "excluded_accounts must list 12-digit AWS account IDs",
        "98765432101",
    ),
    (
        "excluded-account-dashes",
        {"excluded_accounts": ["9876-5432-1012"]},
        "excluded_accounts must list 12-digit AWS account IDs",
        "9876-5432-1012",
    ),
    (
        "excluded-account-letters",
        {"excluded_accounts": ["98765432101x"]},
        "excluded_accounts must list 12-digit AWS account IDs",
        "98765432101x",
    ),
    (
        "excluded-accounts-repeated",
        {"excluded_accounts": ["987654321012", "987654321012"]},
        "excluded_accounts must not list an account ID twice",
        "987654321012",
    ),
]

# The accept rules' messages: each names the input, and ends with the ids of the rules it refuses.
ID_MESSAGE = (
    "accept_rules: a rule's id must be 1 to 64 lowercase letters, digits or hyphens, starting with a"
    " letter or digit"
)
ID_TWICE_MESSAGE = "accept_rules: no two rules may have the same id"
KIND_MESSAGE = "accept_rules: a rule's kind must be threat_response or vuln_remediation"
REASON_MESSAGE = "accept_rules: a rule must give its reason"
REVIEW_BY_MESSAGE = "accept_rules: a rule's review_by must be a date, YYYY-MM-DD"
DECISION_REF_MESSAGE = (
    "accept_rules: a rule's decision_ref must be its register entry's Linear issue identifier,"
    " such as SEC-42"
)
THREAT_WHAT_MESSAGE = (
    "accept_rules: a threat_response rule must name the finding_types it accepts"
)
VULN_WHAT_MESSAGE = "accept_rules: a vuln_remediation rule must name the cves it accepts or the package, not both"
FINDING_TYPE_MESSAGE = (
    "accept_rules: finding_types must be GuardDuty finding types, each in full, such as"
    " Recon:EC2/PortProbeUnprotectedPort"
)
CVE_MESSAGE = (
    "accept_rules: cves must be CVE identifiers, each in full, such as CVE-2024-12797"
)
PACKAGE_MESSAGE = "accept_rules: a package must have a name and a version, each in full"
WHERE_MESSAGE = (
    "accept_rules: a rule's where must name resource_ids, tags or image_repositories; accounts only"
    " narrows them"
)
ACCOUNTS_MESSAGE = "accept_rules: where.accounts must list 12-digit AWS account IDs"
WHERE_VALUES_MESSAGE = "accept_rules: where's resource_ids, image_repositories and tags must be values in full"
THREAT_OTHER_MESSAGE = "accept_rules: a threat_response rule must not name cves, a package or image_repositories"
VULN_OTHER_MESSAGE = "accept_rules: a vuln_remediation rule must not name finding_types or be a behavioral_exception"
SIZE_MESSAGE = "accept_rules: a rule must fit in 4096 characters as JSON"
# What a Standard SSM parameter holds.
STANDARD_PARAMETER_LIMIT = 4096
# Drops a field from a rule.
MISSING = object()


def rule(base: Dict[str, Any] = None, **changes: Any) -> Dict[str, Any]:
    """
    :param base: The rule to start from; :data:`THREAT_RULE` when ``None``.
    :param changes: Fields to replace, or to drop with :data:`MISSING`.
    :return: A copy of the rule with the changes.
    """
    changed = deepcopy(THREAT_RULE if base is None else base)
    for field, value in changes.items():
        if value is MISSING:
            del changed[field]
        else:
            changed[field] = value
    return changed


def rule_of_length(length: int) -> Dict[str, Any]:
    """
    :param length: How many characters the rule's published value should have.
    :return: A valid rule whose published value has exactly that many, by the length of its reason.
    """
    base = rule(VULN_PACKAGE_RULE, id="long-reason", reason="")
    return rule(base, reason="x" * (length - len(terraform_json(published_rule(base)))))


# Each case: the rules, the message, and the ids it should name; None when Terraform's own type check
# refuses the rules, whose message names the rule's place in the list.
ACCEPT_RULES_CASES = [
    ("id-uppercase", [rule(id="Vpn-Port-Probes")], ID_MESSAGE, ["Vpn-Port-Probes"]),
    ("id-underscore", [rule(id="vpn_port_probes")], ID_MESSAGE, ["vpn_port_probes"]),
    ("id-leading-hyphen", [rule(id="-vpn")], ID_MESSAGE, ["-vpn"]),
    ("id-too-long", [rule(id="a" * 65)], ID_MESSAGE, ["a" * 65]),
    ("id-empty", [rule(id="")], ID_MESSAGE, [""]),
    (
        "id-twice",
        [rule(), rule(VULN_CVE_RULE, id=THREAT_RULE["id"])],
        ID_TWICE_MESSAGE,
        [THREAT_RULE["id"]],
    ),
    ("kind-missing", [rule(kind=MISSING)], KIND_MESSAGE, [THREAT_RULE["id"]]),
    ("kind-unknown", [rule(kind="threat")], KIND_MESSAGE, [THREAT_RULE["id"]]),
    ("reason-missing", [rule(reason=MISSING)], REASON_MESSAGE, [THREAT_RULE["id"]]),
    ("reason-blank", [rule(reason="  ")], REASON_MESSAGE, [THREAT_RULE["id"]]),
    (
        "review-by-missing",
        [rule(review_by=MISSING)],
        REVIEW_BY_MESSAGE,
        [THREAT_RULE["id"]],
    ),
    (
        "review-by-unpadded",
        [rule(review_by="2027-3-31")],
        REVIEW_BY_MESSAGE,
        [THREAT_RULE["id"]],
    ),
    (
        "review-by-no-such-day",
        [rule(review_by="2027-02-30")],
        REVIEW_BY_MESSAGE,
        [THREAT_RULE["id"]],
    ),
    (
        "review-by-timestamp",
        [rule(review_by="2027-03-31T00:00:00Z")],
        REVIEW_BY_MESSAGE,
        [THREAT_RULE["id"]],
    ),
    (
        "decision-ref-missing",
        [rule(decision_ref=MISSING)],
        DECISION_REF_MESSAGE,
        [THREAT_RULE["id"]],
    ),
    (
        "decision-ref-lowercase",
        [rule(decision_ref="sec-42")],
        DECISION_REF_MESSAGE,
        [THREAT_RULE["id"]],
    ),
    (
        "decision-ref-url",
        [rule(decision_ref="https://linear.app/acme/issue/SEC-42")],
        DECISION_REF_MESSAGE,
        [THREAT_RULE["id"]],
    ),
    (
        "threat-without-finding-types",
        [rule(finding_types=MISSING)],
        THREAT_WHAT_MESSAGE,
        [THREAT_RULE["id"]],
    ),
    (
        "threat-finding-types-empty",
        [rule(finding_types=[])],
        THREAT_WHAT_MESSAGE,
        [THREAT_RULE["id"]],
    ),
    (
        "finding-type-wildcard",
        [rule(finding_types=["Recon:EC2/PortProbe*"])],
        FINDING_TYPE_MESSAGE,
        [THREAT_RULE["id"]],
    ),
    (
        "finding-type-purpose-only",
        [rule(finding_types=["Recon"])],
        FINDING_TYPE_MESSAGE,
        [THREAT_RULE["id"]],
    ),
    (
        "finding-type-no-purpose",
        [rule(finding_types=["PortProbeUnprotectedPort"])],
        FINDING_TYPE_MESSAGE,
        [THREAT_RULE["id"]],
    ),
    (
        "vuln-without-what",
        [rule(VULN_CVE_RULE, cves=MISSING)],
        VULN_WHAT_MESSAGE,
        [VULN_CVE_RULE["id"]],
    ),
    (
        "vuln-cves-empty",
        [rule(VULN_CVE_RULE, cves=[])],
        VULN_WHAT_MESSAGE,
        [VULN_CVE_RULE["id"]],
    ),
    (
        "vuln-cves-and-package",
        [rule(VULN_CVE_RULE, package=VULN_PACKAGE_RULE["package"])],
        VULN_WHAT_MESSAGE,
        [VULN_CVE_RULE["id"]],
    ),
    (
        "cve-lowercase",
        [rule(VULN_CVE_RULE, cves=["cve-2024-12797"])],
        CVE_MESSAGE,
        [VULN_CVE_RULE["id"]],
    ),
    (
        "cve-wildcard",
        [rule(VULN_CVE_RULE, cves=["CVE-2024-*"])],
        CVE_MESSAGE,
        [VULN_CVE_RULE["id"]],
    ),
    (
        "package-without-version",
        [rule(VULN_PACKAGE_RULE, package={"name": "glibc"})],
        PACKAGE_MESSAGE,
        [VULN_PACKAGE_RULE["id"]],
    ),
    (
        "package-without-name",
        [rule(VULN_PACKAGE_RULE, package={"version": "2.26-64.amzn2.0.1"})],
        PACKAGE_MESSAGE,
        [VULN_PACKAGE_RULE["id"]],
    ),
    (
        "package-version-wildcard",
        [rule(VULN_PACKAGE_RULE, package={"name": "glibc", "version": "2.26*"})],
        PACKAGE_MESSAGE,
        [VULN_PACKAGE_RULE["id"]],
    ),
    ("where-missing", [rule(where=MISSING)], WHERE_MESSAGE, [THREAT_RULE["id"]]),
    ("where-empty", [rule(where={})], WHERE_MESSAGE, [THREAT_RULE["id"]]),
    (
        "where-accounts-alone",
        [rule(where={"accounts": ["111122223333"]})],
        WHERE_MESSAGE,
        [THREAT_RULE["id"]],
    ),
    (
        "where-empty-selectors",
        [rule(where={"resource_ids": [], "tags": {}, "accounts": ["111122223333"]})],
        WHERE_MESSAGE,
        [THREAT_RULE["id"]],
    ),
    (
        "where-account-short",
        [rule(where={"tags": {"role": "vpn"}, "accounts": ["11112222333"]})],
        ACCOUNTS_MESSAGE,
        [THREAT_RULE["id"]],
    ),
    (
        "where-resource-id-wildcard",
        [rule(where={"resource_ids": ["*"]})],
        WHERE_VALUES_MESSAGE,
        [THREAT_RULE["id"]],
    ),
    (
        "where-resource-id-empty",
        [rule(where={"resource_ids": [""]})],
        WHERE_VALUES_MESSAGE,
        [THREAT_RULE["id"]],
    ),
    (
        "where-tag-value-wildcard",
        [rule(where={"tags": {"role": "vpn*"}})],
        WHERE_VALUES_MESSAGE,
        [THREAT_RULE["id"]],
    ),
    (
        "where-image-repository-wildcard",
        [rule(VULN_CVE_RULE, where={"image_repositories": ["batch-*"]})],
        WHERE_VALUES_MESSAGE,
        [VULN_CVE_RULE["id"]],
    ),
    (
        "threat-with-cves",
        [rule(cves=VULN_CVE_RULE["cves"])],
        THREAT_OTHER_MESSAGE,
        [THREAT_RULE["id"]],
    ),
    (
        "threat-with-package",
        [rule(package=VULN_PACKAGE_RULE["package"])],
        THREAT_OTHER_MESSAGE,
        [THREAT_RULE["id"]],
    ),
    (
        "threat-with-image-repositories",
        [rule(where={**THREAT_RULE["where"], "image_repositories": ["batch-worker"]})],
        THREAT_OTHER_MESSAGE,
        [THREAT_RULE["id"]],
    ),
    (
        "vuln-with-finding-types",
        [rule(VULN_CVE_RULE, finding_types=THREAT_RULE["finding_types"])],
        VULN_OTHER_MESSAGE,
        [VULN_CVE_RULE["id"]],
    ),
    (
        "vuln-behavioral-exception",
        [rule(VULN_CVE_RULE, behavioral_exception=True)],
        VULN_OTHER_MESSAGE,
        [VULN_CVE_RULE["id"]],
    ),
    (
        "two-rules-refused",
        [rule(id="first", reason=MISSING), rule(VULN_CVE_RULE, id="second", reason="")],
        REASON_MESSAGE,
        ["first", "second"],
    ),
    (
        "over-a-standard-parameter",
        [rule_of_length(STANDARD_PARAMETER_LIMIT + 1)],
        SIZE_MESSAGE,
        ["long-reason"],
    ),
    # Terraform's type check: its message names the input, and the rule by its place in the list.
    (
        "finding-types-not-a-list",
        [rule(finding_types="Recon:EC2/PortProbeUnprotectedPort")],
        'attribute "finding_types": list of string required',
        None,
    ),
    (
        "id-missing",
        [rule(id=MISSING)],
        'attribute "id" is required',
        None,
    ),
]


def rule_values(rules: List[Dict[str, Any]]) -> List[str]:
    """
    :param rules: Rules a case passes.
    :return: Every value they hold, but their ids and kinds, which the messages may name, and values
        short enough to occur in a message by chance.
    """

    def leaves(value: Any) -> List[str]:
        # A map's values, not its keys: a tag key such as "role" may occur in Terraform's output.
        if isinstance(value, dict):
            return [leaf for item in value.values() for leaf in leaves(item)]
        if isinstance(value, (list, tuple)):
            return [leaf for item in value for leaf in leaves(item)]
        return [value] if isinstance(value, str) else []

    return [
        value
        for one in rules
        for field, content in one.items()
        if field not in ("id", "kind")
        for value in leaves(content)
        if len(value.strip()) > 3
    ]


# Contents of the ExternalIds parameter that the module refuses, at plan, without echoing them.
EXTERNAL_IDS_CASES = [
    ("placeholder", PLACEHOLDER, "still holds the placeholder"),
    ("not-json", EXTERNAL_ID, SHAPE_MESSAGE),
    ("json-string", json.dumps(EXTERNAL_ID), SHAPE_MESSAGE),
    ("json-object", json.dumps({"external_id": EXTERNAL_ID}), SHAPE_MESSAGE),
    ("empty-list", "[]", SHAPE_MESSAGE),
    (
        "three",
        json.dumps([EXTERNAL_ID, OTHER_EXTERNAL_ID, new_external_id()]),
        SHAPE_MESSAGE,
    ),
    ("short", json.dumps([EXTERNAL_ID[:42]]), SHAPE_MESSAGE),
    ("bad-character", json.dumps([BAD_EXTERNAL_ID]), SHAPE_MESSAGE),
    ("repeated", json.dumps([EXTERNAL_ID, EXTERNAL_ID]), SHAPE_MESSAGE),
    ("not-a-string", json.dumps([EXTERNAL_ID, 7]), SHAPE_MESSAGE),
]


@pytest.fixture(scope="module")
def parameters(boto3_session, aws_region) -> Iterator[Dict[str, Any]]:
    """
    The two parameters the module reads, in the provider's Region, filled with valid values.
    """
    ssm_client = boto3_session.client("ssm", region_name=aws_region)
    values = {
        EXTERNAL_IDS_PARAMETER: json.dumps([EXTERNAL_ID]),
        REGISTRATION_TOKEN_PARAMETER: new_registration_token(),
    }
    arns = {}
    try:
        for name, value in values.items():
            ssm_client.put_parameter(
                Name=name, Value=value, Type="SecureString", Overwrite=True
            )
            arns[name] = ssm_client.get_parameter(Name=name)["Parameter"]["ARN"]
        yield {"ssm_client": ssm_client, "arns": arns}
    finally:
        ssm_client.delete_parameters(Names=list(values))


def store_external_ids(parameters: Dict[str, Any], value: str) -> None:
    """
    :param parameters: The ``parameters`` fixture.
    :param value: What to put in the ExternalIds parameter.
    """
    parameters["ssm_client"].put_parameter(
        Name=EXTERNAL_IDS_PARAMETER, Value=value, Type="SecureString", Overwrite=True
    )


def tfvars(
    aws_region: str,
    test_role_arn: Optional[str],
    parameters: Dict[str, Any],
    **overrides: Any,
) -> Dict[str, Any]:
    """
    Build valid inputs for the validation root module, with some values replaced.

    :param aws_region: Region for the AWS provider.
    :param test_role_arn: Role that Terraform assumes, if any.
    :param parameters: The ``parameters`` fixture.
    :param overrides: Inputs to replace.
    :return: Variable names and values.
    """
    values = {
        "region": aws_region,
        "role_arn": test_role_arn,
        "environment": "pytest",
        "control_plane_account_id": CONTROL_PLANE_ACCOUNT_ID,
        "external_ids_parameter_arn": parameters["arns"][EXTERNAL_IDS_PARAMETER],
        "registration_token_parameter_arn": parameters["arns"][
            REGISTRATION_TOKEN_PARAMETER
        ],
        "event_bus_arn": EVENT_BUS_ARN,
        "registration_url": "https://api.staging.loopproof.ai/connector/registrations",
        "severities": None,
        "excluded_accounts": None,
        "accept_rules": None,
    }
    values.update(overrides)
    return values


@pytest.fixture(scope="module")
def validation_root(aws_provider_version):
    """The validation root module, initialized once."""
    write_terraform_tf(VALIDATION_ROOT, aws_provider_version)
    terraform_check(VALIDATION_ROOT, "init", "-input=false")
    return VALIDATION_ROOT


@pytest.mark.parametrize(
    "aws_provider_version", ["~> 6.0"], ids=["aws-6"], scope="module"
)
@pytest.mark.parametrize(
    "overrides, external_ids",
    [
        ({}, [EXTERNAL_ID]),
        ({}, [EXTERNAL_ID, OTHER_EXTERNAL_ID]),
        (
            {"registration_url": "http://127.0.0.1:8080/connector/registrations"},
            [EXTERNAL_ID],
        ),
        (
            {"registration_url": "http://localhost/connector/registrations"},
            [EXTERNAL_ID],
        ),
        (
            {
                "severities": [
                    "Unknown",
                    "Informational",
                    "Low",
                    "Medium",
                    "High",
                    "Critical",
                    "Fatal",
                    "Other",
                ]
            },
            [EXTERNAL_ID],
        ),
        ({"environment": "production-eu-1"}, [EXTERNAL_ID]),
        ({"excluded_accounts": []}, [EXTERNAL_ID]),
        ({"excluded_accounts": ["987654321012", "210987654321"]}, [EXTERNAL_ID]),
        ({"accept_rules": []}, [EXTERNAL_ID]),
        ({"accept_rules": [THREAT_RULE]}, [EXTERNAL_ID]),
        ({"accept_rules": [VULN_CVE_RULE]}, [EXTERNAL_ID]),
        ({"accept_rules": [VULN_PACKAGE_RULE]}, [EXTERNAL_ID]),
        ({"accept_rules": [EXCEPTION_RULE]}, [EXTERNAL_ID]),
        (
            {
                "accept_rules": [
                    THREAT_RULE,
                    VULN_CVE_RULE,
                    VULN_PACKAGE_RULE,
                    EXCEPTION_RULE,
                ]
            },
            [EXTERNAL_ID],
        ),
        (
            {
                "accept_rules": [
                    rule(
                        id="a" * 64,
                        where={"resource_ids": ["i-0123456789abcdef0"]},
                        review_by="2028-02-29",
                        decision_ref="RISK2-1",
                    )
                ]
            },
            [EXTERNAL_ID],
        ),
        (
            {"accept_rules": [rule_of_length(STANDARD_PARAMETER_LIMIT)]},
            [EXTERNAL_ID],
        ),
    ],
    ids=[
        "defaults",
        "two-external-ids",
        "url-loopback",
        "url-localhost",
        "all-severities",
        "environment-hyphens",
        "excluded-accounts-empty",
        "excluded-accounts-two",
        "accept-rules-empty",
        "accept-rules-threat",
        "accept-rules-vuln-cves",
        "accept-rules-vuln-package",
        "accept-rules-exception",
        "accept-rules-each-kind",
        "accept-rules-limits",
        "accept-rules-standard-parameter-full",
    ],
)
def test_valid_inputs(
    validation_root, parameters, aws_region, test_role_arn, overrides, external_ids
):
    """Valid inputs plan cleanly, so the failures below come from the bad value alone."""
    store_external_ids(parameters, json.dumps(external_ids))
    write_tfvars(
        validation_root, tfvars(aws_region, test_role_arn, parameters, **overrides)
    )
    log = terraform_check(validation_root, "plan", "-input=false")
    for external_id in external_ids:
        assert external_id not in log


@pytest.mark.parametrize(
    "aws_provider_version", ["~> 6.0"], ids=["aws-6"], scope="module"
)
@pytest.mark.parametrize(
    "overrides, message, secret",
    [case[1:] for case in CASES],
    ids=[case[0] for case in CASES],
)
def test_invalid_inputs(
    validation_root, parameters, aws_region, test_role_arn, overrides, message, secret
):
    """A bad value fails the plan with a message that names the problem, without echoing secrets."""
    store_external_ids(parameters, json.dumps([EXTERNAL_ID]))
    write_tfvars(
        validation_root, tfvars(aws_region, test_role_arn, parameters, **overrides)
    )
    result = terraform(validation_root, "plan", "-input=false")

    assert result.returncode != 0
    assert message in printed(result)
    if secret is not None:
        assert secret not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "aws_provider_version", ["~> 6.0"], ids=["aws-6"], scope="module"
)
@pytest.mark.parametrize(
    "value, message",
    [case[1:] for case in EXTERNAL_IDS_CASES],
    ids=[case[0] for case in EXTERNAL_IDS_CASES],
)
def test_invalid_external_ids(
    validation_root, parameters, aws_region, test_role_arn, value, message
):
    """
    Bad contents of the ExternalIds parameter fail the plan with one message, which names the
    parameter and doesn't echo what it holds. The placeholder is caught before the JSON is decoded.
    """
    store_external_ids(parameters, value)
    write_tfvars(validation_root, tfvars(aws_region, test_role_arn, parameters))
    result = terraform(validation_root, "plan", "-input=false")
    output = result.stdout + result.stderr

    assert result.returncode != 0
    assert f"{parameters['arns'][EXTERNAL_IDS_PARAMETER]} {message}" in printed(result)
    assert output.count("Error:") == 1, output
    for external_id in [
        EXTERNAL_ID,
        EXTERNAL_ID[:42],
        BAD_EXTERNAL_ID,
        OTHER_EXTERNAL_ID,
    ]:
        assert external_id not in output


@pytest.mark.parametrize(
    "aws_provider_version", ["~> 6.0"], ids=["aws-6"], scope="module"
)
@pytest.mark.parametrize(
    "rules, message, rule_ids",
    [case[1:] for case in ACCEPT_RULES_CASES],
    ids=[case[0] for case in ACCEPT_RULES_CASES],
)
def test_invalid_accept_rules(
    validation_root, parameters, aws_region, test_role_arn, rules, message, rule_ids
):
    """
    A rule of the wrong shape fails the plan, before anything is published, with a message that names
    the input and the ids of the rules it refuses, and no other value of theirs.
    """
    store_external_ids(parameters, json.dumps([EXTERNAL_ID]))
    write_tfvars(
        validation_root,
        tfvars(aws_region, test_role_arn, parameters, accept_rules=rules),
    )
    result = terraform(validation_root, "plan", "-input=false")
    output = result.stdout + result.stderr

    assert result.returncode != 0
    assert message in printed(result)
    assert "accept_rules" in printed(result)
    if rule_ids is not None:
        named = ", ".join(json.dumps(rule_id) for rule_id in rule_ids)
        assert f"{message}. Rules: {named}." in printed(result)
    for value in rule_values(rules):
        assert value not in output, value
