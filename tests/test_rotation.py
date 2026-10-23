"""
ExternalId rotation without a failed AssumeRole: the tenant puts [old], then [old, new], then [new] in
the ExternalIds parameter, applying after each step. The Terraform doesn't change.

Right after a trust policy change, some STS hosts keep using the previous policy for minutes. In the
test account, a newly added ExternalId was refused now and then for several minutes after the change,
while a value listed both before and after it was never refused. So each step waits until the value
it adds or removes has settled, and checks the value that must keep working on every poll: a single
denial for it fails the test.
"""

import pytest

from tests.conftest import (
    CONNECTOR_ROOT,
    ConnectorProbe,
    connector_applied,
    connector_tfvars,
    fill_parameters,
    new_external_id,
    new_registration_token,
    terraform_check,
    wait_until_settled,
    write_terraform_tf,
    write_tfvars,
)

# How long a change must hold on every poll before the next step, and how long a step may take.
SETTLE_SECONDS = 300
STEP_TIMEOUT = 1800


@pytest.mark.parametrize("aws_provider_version", ["~> 6.0"], ids=["aws-6"])
def test_rotation(
    aws_provider_version,
    aws_region,
    test_role_arn,
    keep_after,
    boto3_session,
    ssm_client,
    registration_server,
):
    old = new_external_id()
    new = new_external_id()

    def apply_with(external_ids):
        fill_parameters(ssm_client, external_ids=external_ids)
        log = terraform_check(CONNECTOR_ROOT, "apply", "-input=false", "-auto-approve")
        # The trust policy, in place.
        assert "Resources: 0 added, 1 changed, 0 destroyed." in log

    write_terraform_tf(CONNECTOR_ROOT, aws_provider_version)
    write_tfvars(
        CONNECTOR_ROOT,
        connector_tfvars(aws_region, test_role_arn, registration_server.url),
    )

    # Step 1: [old]. The role is new, so old may be refused now and then until IAM settles.
    with connector_applied(
        CONNECTOR_ROOT,
        ssm_client,
        [old],
        new_registration_token(),
        destroy_after=not keep_after,
    ) as (outputs, _):
        probe_role_arn = outputs["probe_role_arn"]
        probe = ConnectorProbe(boto3_session, aws_region, outputs["role_arn"])
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

        # The trust policy changed in place; the role, and so its registration, stayed.
        assert len(registration_server.requests) == 1
