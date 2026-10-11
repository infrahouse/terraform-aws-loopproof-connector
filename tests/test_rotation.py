"""
ExternalId rotation without a failed AssumeRole: apply with [old], then [old, new], then [new].

IAM takes a while to apply a trust policy change. The test waits for the value that is being
added or removed, but the value that must keep working is checked on every poll, so a single
denial for it fails the test.
"""

import pytest
from pytest_infrahouse import terraform_apply

from tests.conftest import (
    CONNECTOR_ROOT,
    REGISTRATION_PATH,
    ConnectorProbe,
    connector_tfvars,
    new_external_id,
    wait_for,
    write_terraform_tf,
    write_tfvars,
)

# No registration token, so the module never calls this URL.
UNUSED_REGISTRATION_URL = f"http://127.0.0.1:9{REGISTRATION_PATH}"


@pytest.mark.parametrize("aws_provider_version", ["~> 6.0"], ids=["aws-6"])
def test_rotation(
    aws_provider_version, aws_region, test_role_arn, keep_after, boto3_session
):
    old = new_external_id()
    new = new_external_id()

    def apply_with(external_ids):
        write_tfvars(
            CONNECTOR_ROOT,
            connector_tfvars(
                aws_region, test_role_arn, external_ids, UNUSED_REGISTRATION_URL
            ),
        )

    write_terraform_tf(CONNECTOR_ROOT, aws_provider_version)

    # Step 1: [old]
    apply_with([old])
    with terraform_apply(
        CONNECTOR_ROOT, destroy_after=not keep_after, json_output=True
    ) as tf_output:
        probe_role_arn = tf_output["probe_role_arn"]["value"]
        probe = ConnectorProbe(
            boto3_session, aws_region, tf_output["role_arn"]["value"]
        )
        wait_for(
            lambda: probe.can_assume(probe_role_arn, old),
            "the connector role accepts the old ExternalId",
        )
        assert not probe.can_assume(
            probe_role_arn, new
        ), "the new ExternalId works before it was added"

        # Step 2: [old, new]. Both work; old never stops working.
        apply_with([old, new])
        with terraform_apply(CONNECTOR_ROOT, destroy_after=False, json_output=False):
            pass

        def new_works_and_old_still_does() -> bool:
            assert probe.can_assume(
                probe_role_arn, old
            ), "the old ExternalId was denied while both were listed"
            return probe.can_assume(probe_role_arn, new)

        wait_for(
            new_works_and_old_still_does,
            "the connector role accepts the new ExternalId",
        )
        assert probe.can_assume(
            probe_role_arn, old
        ), "the old ExternalId was denied while both were listed"

        # Step 3: [new]. The old one is denied; new never stops working.
        apply_with([new])
        with terraform_apply(CONNECTOR_ROOT, destroy_after=False, json_output=False):
            pass

        def old_denied_and_new_still_works() -> bool:
            assert probe.can_assume(
                probe_role_arn, new
            ), "the new ExternalId was denied after the rotation"
            return not probe.can_assume(probe_role_arn, old)

        wait_for(
            old_denied_and_new_still_works,
            "the connector role refuses the old ExternalId",
        )
        assert probe.can_assume(
            probe_role_arn, new
        ), "the new ExternalId was denied after the rotation"
