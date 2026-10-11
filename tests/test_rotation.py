"""
ExternalId rotation without a failed AssumeRole: apply with [old], then [old, new], then [new].

Right after a trust policy change, some STS hosts keep using the previous policy for minutes. In the
test account, a newly added ExternalId was refused now and then for several minutes after the change,
while a value listed both before and after it was never refused. So each step waits until the value
it adds or removes has settled, and checks the value that must keep working on every poll: a single
denial for it fails the test.
"""

import pytest
from pytest_infrahouse import terraform_apply

from tests.conftest import (
    CONNECTOR_ROOT,
    REGISTRATION_PATH,
    TFVARS_FILE,
    ConnectorProbe,
    connector_tfvars,
    new_external_id,
    wait_until_settled,
    write_terraform_tf,
    write_tfvars,
)

# No registration token, so the module never calls this URL.
UNUSED_REGISTRATION_URL = f"http://127.0.0.1:9{REGISTRATION_PATH}"

# How long a change must hold on every poll before the next step, and how long a step may take.
SETTLE_SECONDS = 300
STEP_TIMEOUT = 1800


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

    # Step 1: [old]. The role is new, so old may be refused now and then until IAM settles.
    apply_with([old])
    with terraform_apply(
        CONNECTOR_ROOT,
        destroy_after=not keep_after,
        json_output=True,
        var_file=TFVARS_FILE,
    ) as tf_output:
        probe_role_arn = tf_output["probe_role_arn"]["value"]
        probe = ConnectorProbe(
            boto3_session, aws_region, tf_output["role_arn"]["value"]
        )
        wait_until_settled(
            lambda: probe.can_assume(probe_role_arn, old),
            "the connector role accepts the old ExternalId",
            SETTLE_SECONDS,
            STEP_TIMEOUT,
        )
        assert not probe.can_assume(
            probe_role_arn, new
        ), "the new ExternalId works before it was added"

        # Step 2: [old, new]. Both work; old never stops working.
        apply_with([old, new])
        with terraform_apply(
            CONNECTOR_ROOT, destroy_after=False, json_output=False, var_file=TFVARS_FILE
        ):
            pass

        def old_works() -> None:
            assert probe.can_assume(
                probe_role_arn, old
            ), "the old ExternalId was denied while both were listed"

        def new_works_and_old_still_does() -> bool:
            old_works()
            return probe.can_assume(probe_role_arn, new)

        wait_until_settled(
            new_works_and_old_still_does,
            "the connector role accepts the new ExternalId",
            SETTLE_SECONDS,
            STEP_TIMEOUT,
        )

        # Step 3: [new]. The old one is denied; new never stops working.
        apply_with([new])
        with terraform_apply(
            CONNECTOR_ROOT, destroy_after=False, json_output=False, var_file=TFVARS_FILE
        ):
            pass

        def old_denied_and_new_still_works() -> bool:
            assert probe.can_assume(
                probe_role_arn, new
            ), "the new ExternalId was denied after the rotation"
            return not probe.can_assume(probe_role_arn, old)

        wait_until_settled(
            old_denied_and_new_still_works,
            "the connector role refuses the old ExternalId",
            SETTLE_SECONDS,
            STEP_TIMEOUT,
        )
