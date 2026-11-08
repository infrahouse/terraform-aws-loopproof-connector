"""
Input validation. Each case plans the module with one bad value, either an input or the contents of
the ExternalIds parameter; nothing is created but the two parameters the module reads, which the
tests create and delete themselves.
"""

import json
from copy import deepcopy
from typing import Any, Dict, Iterator, List, Optional, Tuple

import pytest

from tests.conftest import (
    EXCEPTION_RULE,
    PLACEHOLDER,
    STANDARD_PARAMETER_LIMIT,
    THREAT_KIND,
    THREAT_RULE,
    VALIDATION_ROOT,
    new_external_id,
    new_registration_token,
    printed,
    published_rule,
    rule_of_length,
    ssm_length,
    terraform,
    terraform_check,
    terraform_json,
    VULN_CVE_RULE,
    VULN_CVES_IN_PACKAGE_RULE,
    VULN_CVES_IN_VERSION_RULE,
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

# The accept rules' inputs, and their messages: each names the input, and ends with the ids of the rules it
# refuses. "{input}" is the input's name.
THREATS = "threat_accept_rules"
VULNS = "vulnerability_accept_rules"
NULL_MESSAGE = "{input} must not hold a null rule"
ID_MESSAGE = (
    "{input}: a rule's id must be 1 to 64 lowercase letters, digits or hyphens, starting with a"
    " letter or digit"
)
ID_TWICE_MESSAGE = "{input}: no two rules may have the same id"
ID_IN_BOTH_MESSAGE = f"{VULNS}: a rule's id must not be a {THREATS} rule's id too"
REASON_MESSAGE = "{input}: a rule must give its reason"
REVIEW_BY_MESSAGE = "{input}: a rule's review_by must be a date, YYYY-MM-DD"
DECISION_REF_MESSAGE = (
    "{input}: a rule's decision_ref must be its register entry's Linear issue identifier,"
    " such as SEC-42"
)
ACCOUNTS_MESSAGE = "{input}: where.accounts must list 12-digit AWS account IDs"
THREAT_WHAT_MESSAGE = f"{THREATS}: a rule must name the finding_types it accepts"
FINDING_TYPE_MESSAGE = (
    f"{THREATS}: finding_types must be GuardDuty finding types, each in full, such as"
    " Recon:EC2/PortProbeUnprotectedPort"
)
VULN_WHAT_MESSAGE = f"{VULNS}: a rule must name the cves it accepts, a package, or both"
CVE_MESSAGE = (
    f"{VULNS}: cves must be CVE identifiers, each in full, such as CVE-2024-12797"
)
PACKAGE_NAME_MESSAGE = f"{VULNS}: a package must have its name"
PACKAGE_VERSION_MESSAGE = (
    f"{VULNS}: a package must have its version, unless the rule names cves"
)
PACKAGE_VALUES_MESSAGE = f"{VULNS}: a package's name and version must be in full"
# What differs between the inputs: the where selectors, and the lists a value may not repeat in.
WHERE_MESSAGES = {
    THREATS: f"{THREATS}: a rule's where must name resource_ids or tags; accounts only narrows them",
    VULNS: (
        f"{VULNS}: a rule's where must name resource_ids, tags or image_repositories; accounts only"
        " narrows them"
    ),
}
WHERE_VALUES_MESSAGES = {
    THREATS: f"{THREATS}: where's resource_ids and tags must be values in full",
    VULNS: f"{VULNS}: where's resource_ids, image_repositories and tags must be values in full",
}
REPEAT_MESSAGES = {
    THREATS: (
        f"{THREATS}: a rule must not list a value twice in finding_types, where.resource_ids or"
        " where.accounts"
    ),
    VULNS: (
        f"{VULNS}: a rule must not list a value twice in cves, where.resource_ids,"
        " where.image_repositories or where.accounts"
    ),
}
SIZE_MESSAGE = "{input}: a rule must fit in 4096 characters as JSON"
# Characters SSM counts twice, or on their own: an emoji, outside the Basic Multilingual Plane, and a q
# with a combining acute, which has no precomposed form, so Terraform's normalization leaves it two.
EMOJI = "\U0001f600"
COMBINING = "q́"
# Drops a field from a rule.
MISSING = object()


def rule(base: Dict[str, Any], **changes: Any) -> Dict[str, Any]:
    """
    :param base: The rule to start from.
    :param changes: Fields to replace, or to drop with :data:`MISSING`.
    :return: A copy of the rule with the changes.
    """
    changed = deepcopy(base)
    for field, value in changes.items():
        if value is MISSING:
            del changed[field]
        else:
            changed[field] = value
    return changed


def common_cases(name: str, base: Dict[str, Any]) -> List[Tuple[Any, ...]]:
    """
    The checks both inputs make, each with its own copy in variables.tf, so each is tried on both.

    :param name: The input, :data:`THREATS` or :data:`VULNS`.
    :param base: A valid rule of that input.
    :return: Cases as :data:`ACCEPT_RULES_CASES` holds them, their names prefixed with the input's kind.
    """
    prefix = "threat" if name == THREATS else "vuln"
    rule_id = base["id"]

    def case(
        label: str, rules: List[Any], template: str, ids: Optional[List[str]]
    ) -> Tuple[Any, ...]:
        return f"{prefix}-{label}", {name: rules}, template.format(input=name), ids

    return [
        case("null-rule", [None], NULL_MESSAGE, None),
        case(
            "id-uppercase",
            [rule(base, id="Vpn-Port-Probes")],
            ID_MESSAGE,
            ["Vpn-Port-Probes"],
        ),
        case(
            "id-underscore",
            [rule(base, id="vpn_port_probes")],
            ID_MESSAGE,
            ["vpn_port_probes"],
        ),
        case("id-leading-hyphen", [rule(base, id="-vpn")], ID_MESSAGE, ["-vpn"]),
        case("id-too-long", [rule(base, id="a" * 65)], ID_MESSAGE, ["a" * 65]),
        case("id-empty", [rule(base, id="")], ID_MESSAGE, [""]),
        case(
            "id-twice",
            [base, rule(base, reason="The same rule, written twice")],
            ID_TWICE_MESSAGE,
            [rule_id],
        ),
        case("reason-missing", [rule(base, reason=MISSING)], REASON_MESSAGE, [rule_id]),
        case("reason-blank", [rule(base, reason="  ")], REASON_MESSAGE, [rule_id]),
        case(
            "review-by-missing",
            [rule(base, review_by=MISSING)],
            REVIEW_BY_MESSAGE,
            [rule_id],
        ),
        case(
            "review-by-unpadded",
            [rule(base, review_by="2027-3-31")],
            REVIEW_BY_MESSAGE,
            [rule_id],
        ),
        case(
            "review-by-no-such-day",
            [rule(base, review_by="2027-02-30")],
            REVIEW_BY_MESSAGE,
            [rule_id],
        ),
        case(
            "review-by-timestamp",
            [rule(base, review_by="2027-03-31T00:00:00Z")],
            REVIEW_BY_MESSAGE,
            [rule_id],
        ),
        case(
            "decision-ref-missing",
            [rule(base, decision_ref=MISSING)],
            DECISION_REF_MESSAGE,
            [rule_id],
        ),
        case(
            "decision-ref-lowercase",
            [rule(base, decision_ref="sec-42")],
            DECISION_REF_MESSAGE,
            [rule_id],
        ),
        case(
            "decision-ref-url",
            [rule(base, decision_ref="https://linear.app/acme/issue/SEC-42")],
            DECISION_REF_MESSAGE,
            [rule_id],
        ),
        case(
            "where-missing",
            [rule(base, where=MISSING)],
            WHERE_MESSAGES[name],
            [rule_id],
        ),
        case("where-empty", [rule(base, where={})], WHERE_MESSAGES[name], [rule_id]),
        case(
            "where-accounts-alone",
            [rule(base, where={"accounts": ["111122223333"]})],
            WHERE_MESSAGES[name],
            [rule_id],
        ),
        case(
            "where-empty-selectors",
            [
                rule(
                    base,
                    where={
                        "resource_ids": [],
                        "tags": {},
                        **({"image_repositories": []} if name == VULNS else {}),
                        "accounts": ["111122223333"],
                    },
                )
            ],
            WHERE_MESSAGES[name],
            [rule_id],
        ),
        case(
            "where-account-short",
            [rule(base, where={"tags": {"role": "vpn"}, "accounts": ["11112222333"]})],
            ACCOUNTS_MESSAGE,
            [rule_id],
        ),
        case(
            "where-resource-id-wildcard",
            [rule(base, where={"resource_ids": ["*"]})],
            WHERE_VALUES_MESSAGES[name],
            [rule_id],
        ),
        case(
            "where-resource-id-empty",
            [rule(base, where={"resource_ids": [""]})],
            WHERE_VALUES_MESSAGES[name],
            [rule_id],
        ),
        case(
            "where-tag-value-wildcard",
            [rule(base, where={"tags": {"role": "vpn*"}})],
            WHERE_VALUES_MESSAGES[name],
            [rule_id],
        ),
        case(
            "where-resource-id-twice",
            [rule(base, where={"resource_ids": ["i-0123456789abcdef0"] * 2})],
            REPEAT_MESSAGES[name],
            [rule_id],
        ),
        case(
            "where-account-twice",
            [
                rule(
                    base,
                    where={"tags": {"role": "vpn"}, "accounts": ["111122223333"] * 2},
                )
            ],
            REPEAT_MESSAGES[name],
            [rule_id],
        ),
        # Terraform's type check: its message names the input, and the rule by its place in the list.
        case(
            "id-missing", [rule(base, id=MISSING)], 'attribute "id" is required', None
        ),
    ]


# Each case: its name, the inputs it sets, the message, and the ids it should name; None when the message
# names no rule, or when Terraform's own type check refuses the rules and names the rule's place in the
# list.
ACCEPT_RULES_CASES = (
    common_cases(THREATS, THREAT_RULE)
    + common_cases(VULNS, VULN_CVE_RULE)
    + [
        (
            "id-in-both-inputs",
            {
                THREATS: [THREAT_RULE],
                VULNS: [rule(VULN_CVE_RULE, id=THREAT_RULE["id"])],
            },
            ID_IN_BOTH_MESSAGE,
            [THREAT_RULE["id"]],
        ),
        (
            "threat-without-finding-types",
            {THREATS: [rule(THREAT_RULE, finding_types=MISSING)]},
            THREAT_WHAT_MESSAGE,
            [THREAT_RULE["id"]],
        ),
        (
            "threat-finding-types-empty",
            {THREATS: [rule(THREAT_RULE, finding_types=[])]},
            THREAT_WHAT_MESSAGE,
            [THREAT_RULE["id"]],
        ),
        (
            "finding-type-wildcard",
            {THREATS: [rule(THREAT_RULE, finding_types=["Recon:EC2/PortProbe*"])]},
            FINDING_TYPE_MESSAGE,
            [THREAT_RULE["id"]],
        ),
        (
            "finding-type-purpose-only",
            {THREATS: [rule(THREAT_RULE, finding_types=["Recon"])]},
            FINDING_TYPE_MESSAGE,
            [THREAT_RULE["id"]],
        ),
        (
            "finding-type-no-purpose",
            {THREATS: [rule(THREAT_RULE, finding_types=["PortProbeUnprotectedPort"])]},
            FINDING_TYPE_MESSAGE,
            [THREAT_RULE["id"]],
        ),
        (
            "finding-type-twice",
            {
                THREATS: [
                    rule(
                        THREAT_RULE,
                        finding_types=["Recon:EC2/PortProbeUnprotectedPort"] * 2,
                    )
                ]
            },
            REPEAT_MESSAGES[THREATS],
            [THREAT_RULE["id"]],
        ),
        (
            "vuln-without-what",
            {VULNS: [rule(VULN_CVE_RULE, cves=MISSING)]},
            VULN_WHAT_MESSAGE,
            [VULN_CVE_RULE["id"]],
        ),
        (
            "vuln-cves-empty",
            {VULNS: [rule(VULN_CVE_RULE, cves=[])]},
            VULN_WHAT_MESSAGE,
            [VULN_CVE_RULE["id"]],
        ),
        (
            "cve-lowercase",
            {VULNS: [rule(VULN_CVE_RULE, cves=["cve-2024-12797"])]},
            CVE_MESSAGE,
            [VULN_CVE_RULE["id"]],
        ),
        (
            "cve-wildcard",
            {VULNS: [rule(VULN_CVE_RULE, cves=["CVE-2024-*"])]},
            CVE_MESSAGE,
            [VULN_CVE_RULE["id"]],
        ),
        (
            "cve-twice",
            {VULNS: [rule(VULN_CVE_RULE, cves=["CVE-2024-12797"] * 2)]},
            REPEAT_MESSAGES[VULNS],
            [VULN_CVE_RULE["id"]],
        ),
        # A package named alone still needs its version; with cves it may go without.
        (
            "package-without-version",
            {VULNS: [rule(VULN_PACKAGE_RULE, package={"name": "glibc"})]},
            PACKAGE_VERSION_MESSAGE,
            [VULN_PACKAGE_RULE["id"]],
        ),
        (
            "package-version-null",
            {
                VULNS: [
                    rule(VULN_PACKAGE_RULE, package={"name": "glibc", "version": None})
                ]
            },
            PACKAGE_VERSION_MESSAGE,
            [VULN_PACKAGE_RULE["id"]],
        ),
        # An empty list of cves names none.
        (
            "package-without-version-cves-empty",
            {VULNS: [rule(VULN_CVES_IN_PACKAGE_RULE, cves=[])]},
            PACKAGE_VERSION_MESSAGE,
            [VULN_CVES_IN_PACKAGE_RULE["id"]],
        ),
        (
            "package-without-name",
            {
                VULNS: [
                    rule(VULN_PACKAGE_RULE, package={"version": "2.26-64.amzn2.0.1"})
                ]
            },
            PACKAGE_NAME_MESSAGE,
            [VULN_PACKAGE_RULE["id"]],
        ),
        (
            "package-without-name-beside-cves",
            {
                VULNS: [
                    rule(
                        VULN_CVES_IN_VERSION_RULE,
                        package={"version": "8.7p1-38.amzn2023.0.4"},
                    )
                ]
            },
            PACKAGE_NAME_MESSAGE,
            [VULN_CVES_IN_VERSION_RULE["id"]],
        ),
        (
            "package-empty-beside-cves",
            {VULNS: [rule(VULN_CVES_IN_PACKAGE_RULE, package={})]},
            PACKAGE_NAME_MESSAGE,
            [VULN_CVES_IN_PACKAGE_RULE["id"]],
        ),
        (
            "package-version-wildcard",
            {
                VULNS: [
                    rule(
                        VULN_PACKAGE_RULE, package={"name": "glibc", "version": "2.26*"}
                    )
                ]
            },
            PACKAGE_VALUES_MESSAGE,
            [VULN_PACKAGE_RULE["id"]],
        ),
        (
            "package-name-wildcard",
            {
                VULNS: [
                    rule(
                        VULN_PACKAGE_RULE,
                        package={"name": "glibc*", "version": "2.26-64.amzn2.0.1"},
                    )
                ]
            },
            PACKAGE_VALUES_MESSAGE,
            [VULN_PACKAGE_RULE["id"]],
        ),
        # A version the rule gives must be in full, cves or not.
        (
            "package-version-wildcard-beside-cves",
            {
                VULNS: [
                    rule(
                        VULN_CVES_IN_VERSION_RULE,
                        package={"name": "openssh", "version": "8.7p1-*"},
                    )
                ]
            },
            PACKAGE_VALUES_MESSAGE,
            [VULN_CVES_IN_VERSION_RULE["id"]],
        ),
        (
            "package-version-empty-beside-cves",
            {
                VULNS: [
                    rule(
                        VULN_CVES_IN_VERSION_RULE,
                        package={"name": "openssh", "version": ""},
                    )
                ]
            },
            PACKAGE_VALUES_MESSAGE,
            [VULN_CVES_IN_VERSION_RULE["id"]],
        ),
        (
            "package-name-whitespace-beside-cves",
            {
                VULNS: [
                    rule(
                        VULN_CVES_IN_PACKAGE_RULE,
                        package={"name": "openssh server"},
                    )
                ]
            },
            PACKAGE_VALUES_MESSAGE,
            [VULN_CVES_IN_PACKAGE_RULE["id"]],
        ),
        (
            "where-image-repository-wildcard",
            {VULNS: [rule(VULN_CVE_RULE, where={"image_repositories": ["batch-*"]})]},
            WHERE_VALUES_MESSAGES[VULNS],
            [VULN_CVE_RULE["id"]],
        ),
        (
            "where-image-repository-twice",
            {
                VULNS: [
                    rule(
                        VULN_CVE_RULE,
                        where={"image_repositories": ["batch-worker"] * 2},
                    )
                ]
            },
            REPEAT_MESSAGES[VULNS],
            [VULN_CVE_RULE["id"]],
        ),
        (
            "two-rules-refused",
            {
                THREATS: [
                    rule(THREAT_RULE, id="first", reason=MISSING),
                    rule(EXCEPTION_RULE, id="second", reason=""),
                ]
            },
            REASON_MESSAGE.format(input=THREATS),
            ["first", "second"],
        ),
        (
            "over-a-standard-parameter",
            {VULNS: [rule_of_length(STANDARD_PARAMETER_LIMIT + 1)]},
            SIZE_MESSAGE.format(input=VULNS),
            ["long-reason"],
        ),
        # SSM counts UTF-16 code units: Terraform's length() counts each of these rules as 4096 characters.
        (
            "over-a-standard-parameter-by-an-emoji",
            {VULNS: [rule_of_length(STANDARD_PARAMETER_LIMIT + 1, tail=EMOJI)]},
            SIZE_MESSAGE.format(input=VULNS),
            ["long-reason"],
        ),
        (
            "over-a-standard-parameter-by-a-combining-mark",
            {VULNS: [rule_of_length(STANDARD_PARAMETER_LIMIT + 1, tail=COMBINING)]},
            SIZE_MESSAGE.format(input=VULNS),
            ["long-reason"],
        ),
        (
            "over-a-standard-parameter-threat",
            {
                THREATS: [
                    rule(
                        THREAT_RULE,
                        reason="x"
                        * (
                            STANDARD_PARAMETER_LIMIT
                            + 1
                            - ssm_length(
                                terraform_json(
                                    published_rule(
                                        rule(THREAT_RULE, reason=""), THREAT_KIND
                                    )
                                )
                            )
                        ),
                    )
                ]
            },
            SIZE_MESSAGE.format(input=THREATS),
            [THREAT_RULE["id"]],
        ),
        # Terraform's type check: its message names the input, and the rule by its place in the list.
        (
            "finding-types-not-a-list",
            {
                THREATS: [
                    rule(
                        THREAT_RULE, finding_types="Recon:EC2/PortProbeUnprotectedPort"
                    )
                ]
            },
            'attribute "finding_types": list of string required',
            None,
        ),
        (
            "cves-not-a-list",
            {VULNS: [rule(VULN_CVE_RULE, cves="CVE-2024-12797")]},
            'attribute "cves": list of string required',
            None,
        ),
    ]
)


def rule_values(inputs: Dict[str, List[Any]]) -> List[str]:
    """
    :param inputs: The accept rules a case passes, by input.
    :return: Every value they hold, but their ids, which the messages name, and values short enough to
        occur in a message by chance.
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
        for rules in inputs.values()
        for one in rules
        if one is not None
        for field, content in one.items()
        if field != "id"
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
        "threat_accept_rules": None,
        "vulnerability_accept_rules": None,
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
        ({THREATS: [], VULNS: []}, [EXTERNAL_ID]),
        ({THREATS: [THREAT_RULE]}, [EXTERNAL_ID]),
        ({VULNS: [VULN_CVE_RULE]}, [EXTERNAL_ID]),
        ({VULNS: [VULN_PACKAGE_RULE]}, [EXTERNAL_ID]),
        ({VULNS: [VULN_CVES_IN_VERSION_RULE]}, [EXTERNAL_ID]),
        ({VULNS: [VULN_CVES_IN_PACKAGE_RULE]}, [EXTERNAL_ID]),
        (
            {
                VULNS: [
                    rule(
                        VULN_CVES_IN_PACKAGE_RULE,
                        package={"name": "openssh", "version": None},
                    )
                ]
            },
            [EXTERNAL_ID],
        ),
        ({THREATS: [EXCEPTION_RULE]}, [EXTERNAL_ID]),
        (
            {
                THREATS: [THREAT_RULE, EXCEPTION_RULE],
                VULNS: [
                    VULN_CVE_RULE,
                    VULN_PACKAGE_RULE,
                    VULN_CVES_IN_PACKAGE_RULE,
                    VULN_CVES_IN_VERSION_RULE,
                ],
            },
            [EXTERNAL_ID],
        ),
        (
            {
                THREATS: [
                    rule(
                        THREAT_RULE,
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
            {VULNS: [rule_of_length(STANDARD_PARAMETER_LIMIT)]},
            [EXTERNAL_ID],
        ),
        (
            {VULNS: [rule_of_length(STANDARD_PARAMETER_LIMIT, tail=EMOJI)]},
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
        "accept-rules-both-empty",
        "accept-rules-threat",
        "accept-rules-vuln-cves",
        "accept-rules-vuln-package",
        "accept-rules-vuln-cves-and-package",
        "accept-rules-vuln-cves-and-package-without-version",
        "accept-rules-vuln-cves-and-package-version-null",
        "accept-rules-exception",
        "accept-rules-each-kind",
        "accept-rules-limits",
        "accept-rules-standard-parameter-full",
        "accept-rules-standard-parameter-full-emoji",
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
    "inputs, message, rule_ids",
    [case[1:] for case in ACCEPT_RULES_CASES],
    ids=[case[0] for case in ACCEPT_RULES_CASES],
)
def test_invalid_accept_rules(
    validation_root, parameters, aws_region, test_role_arn, inputs, message, rule_ids
):
    """
    A rule of the wrong shape fails the plan, before anything is published, with a message that names
    the input and the ids of the rules it refuses, and no other value of theirs.
    """
    store_external_ids(parameters, json.dumps([EXTERNAL_ID]))
    write_tfvars(
        validation_root,
        tfvars(aws_region, test_role_arn, parameters, **inputs),
    )
    result = terraform(validation_root, "plan", "-input=false")

    assert result.returncode != 0
    # The diagnostics, on stderr. stdout holds the plan of the module's other resources, which Terraform
    # prints despite the error, and whose words, such as the event pattern's "product", may hold a value.
    diagnostics = " ".join(result.stderr.split())
    assert message in diagnostics
    for name in inputs:
        assert name in diagnostics
    # What the diagnostics hold beyond the message and the ids it names, which may hold a value by chance,
    # such as the message's example finding type or a package's name inside a rule's id.
    beyond = diagnostics.replace(message, "")
    if rule_ids is not None:
        named = ", ".join(json.dumps(rule_id) for rule_id in rule_ids)
        assert f"{message}. Rules: {named}." in diagnostics
        beyond = beyond.replace(f". Rules: {named}.", "")
    for value in rule_values(inputs):
        assert " ".join(value.split()) not in beyond, value
