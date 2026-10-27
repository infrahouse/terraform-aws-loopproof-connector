"""
The upgrade from the previous release, as a tenant takes it: the connector installed at that release from
the registry, then the module's version changed and applied, and nothing else. One test, so that the steps
run in order.
"""

import json
import os
import subprocess
from os import path as osp
from textwrap import dedent
from typing import Any, Dict, List, Set

import pytest

from tests.conftest import (
    ROLE_ADDRESS,
    RULE_ADDRESS,
    RULE_NAME,
    TEST_ENVIRONMENT,
    UPGRADE_ROOT,
    connector_applied,
    finding_event,
    forwarded,
    forwarding_pattern_document,
    new_external_id,
    new_registration_token,
    terraform,
    terraform_check,
    write_terraform_tf,
    write_tfvars,
)

# The release tenants run before this one.
UPGRADE_FROM_VERSION = "1.1.0"
REGISTRY_SOURCE = "registry.infrahouse.com/infrahouse/loopproof-connector/aws"
# Terraform merges an override file's module block into the root's, so this one swaps the root's source,
# this checkout, for the release on the registry.
OVERRIDE_FILE = osp.join(UPGRADE_ROOT, "main_override.tf")
# All the upgrade may create: nothing.
ADDED: Set[str] = set()
# What it changes in place, and which of their attributes: the forwarding rule's pattern, which forwards
# GuardDuty's findings at every severity, and its description, which says so. At a release, the role's
# module_version tag changes too, and the test checks it apart.
UPDATED = {RULE_ADDRESS: ["description", "event_pattern"]}


def pin_previous_release() -> None:
    """Make the upgrade root's module the previous release, from the registry."""
    with open(OVERRIDE_FILE, "w", encoding="utf-8") as fp:
        fp.write(dedent(f"""\
            module "connector" {{
              source  = "{REGISTRY_SOURCE}"
              version = "{UPGRADE_FROM_VERSION}"
            }}
            """))


def planned_changes(root: str) -> Dict[str, Dict[str, Any]]:
    """
    Read a saved plan's changes. Not through :func:`terraform`, which logs what it prints: the plan's
    JSON holds the ExternalId, in the trust policy.

    :param root: A root module with a saved plan in ``tfplan``.
    :return: Each change by resource address, but those that change nothing.
    """
    result = subprocess.run(
        ["terraform", "show", "-json", "tfplan"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return {
        resource["address"]: resource["change"]
        for resource in json.loads(result.stdout).get("resource_changes", [])
        if resource["change"]["actions"] not in (["no-op"], ["read"])
    }


def changed_keys(before: Dict[str, Any], after: Dict[str, Any]) -> List[str]:
    """
    :param before: A mapping, such as a resource's attributes before a change.
    :param after: The same mapping after it.
    :return: The keys whose values differ, sorted.
    """
    return sorted(
        key for key in set(before) | set(after) if before.get(key) != after.get(key)
    )


@pytest.mark.parametrize("aws_provider_version", ["~> 6.0"], ids=["aws-6"])
def test_upgrade_from_previous_release(
    aws_provider_version,
    aws_region,
    test_role_arn,
    keep_after,
    ssm_client,
    iam_client,
    events_client,
    registration_server,
):
    """
    Changing the version changes the forwarding rule's pattern and description in place, so that a Low
    GuardDuty finding, dropped before, is forwarded after, and at a release the role's module_version tag.
    It creates and replaces nothing, changes no other resource and doesn't register again, and the next
    plan is empty.
    """
    write_terraform_tf(UPGRADE_ROOT, aws_provider_version)
    write_tfvars(
        UPGRADE_ROOT,
        {
            "region": aws_region,
            "role_arn": test_role_arn,
            "environment": TEST_ENVIRONMENT,
            "registration_url": registration_server.url,
        },
    )
    pin_previous_release()
    try:
        with connector_applied(
            UPGRADE_ROOT,
            ssm_client,
            [new_external_id()],
            new_registration_token(),
            destroy_after=not keep_after,
        ) as (outputs, _):
            role_name = outputs["role_name"]
            role = iam_client.get_role(RoleName=role_name)["Role"]
            tags = {tag["Key"]: tag["Value"] for tag in role["Tags"]}
            assert tags["module_version"] == UPGRADE_FROM_VERSION
            assert len(registration_server.requests) == 1
            # The sample is a GuardDuty finding: the previous release forwards it by severity only.
            assert not forwarded(events_client, finding_event("Low"))

            os.remove(OVERRIDE_FILE)
            terraform_check(UPGRADE_ROOT, "init", "-input=false")
            terraform_check(UPGRADE_ROOT, "plan", "-input=false", "-out=tfplan")
            changes = planned_changes(UPGRADE_ROOT)

            # No delete, so no replacement, and nothing created but ADDED.
            assert {
                address: change["actions"]
                for address, change in changes.items()
                if change["actions"] not in (["create"], ["update"])
            } == {}
            assert {
                address
                for address, change in changes.items()
                if change["actions"] == ["create"]
            } == ADDED
            updated = {
                address: change
                for address, change in changes.items()
                if change["actions"] == ["update"]
            }
            # The messages name addresses and attribute names only: the role's before and after hold the
            # ExternalId.
            assert set(updated) - {ROLE_ADDRESS} == set(UPDATED), sorted(updated)
            for address, attributes in UPDATED.items():
                # An attribute unknown until the apply is missing from "after", so it counts as changed.
                changed = changed_keys(
                    updated[address]["before"], updated[address]["after"]
                )
                assert changed == attributes, address
            assert json.loads(
                updated[RULE_ADDRESS]["after"]["event_pattern"]
            ) == forwarding_pattern_document([])
            # At a release, the role's module_version tag, and nothing else of the role.
            if ROLE_ADDRESS in updated:
                change = updated[ROLE_ADDRESS]
                changed = changed_keys(change["before"], change["after"])
                assert set(changed) <= {"tags", "tags_all"}, changed
                for tags in ["tags", "tags_all"]:
                    assert set(
                        changed_keys(change["before"][tags], change["after"][tags])
                    ) <= {"module_version"}

            terraform_check(UPGRADE_ROOT, "apply", "-input=false", "tfplan")
            assert len(registration_server.requests) == 1
            assert json.loads(
                events_client.describe_rule(Name=RULE_NAME)["EventPattern"]
            ) == forwarding_pattern_document([])
            assert forwarded(events_client, finding_event("Low"))
            assert sorted(
                iam_client.list_role_policies(RoleName=role_name)["PolicyNames"]
            ) == [
                "config-aggregator-query",
                "ecr-repository-tags",
                "excluded-accounts-parameter",
                "security-hub-findings",
            ]
            result = terraform(
                UPGRADE_ROOT, "plan", "-input=false", "-detailed-exitcode"
            )
            assert result.returncode == 0, "the plan after the upgrade isn't empty"
    finally:
        if osp.exists(OVERRIDE_FILE):
            os.remove(OVERRIDE_FILE)
