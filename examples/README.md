# Examples

* [basic](basic/): the two parts LoopProof's onboarding generates, in one root: the SSM parameters that hold the
  ExternalIds and the registration token, and the module call with their ARNs.

```bash
cd examples/basic
terraform init
terraform apply \
  -var region=us-east-1 \
  -var environment=production \
  -var control_plane_account_id=123456789012 \
  -var event_bus_arn=arn:aws:events:us-west-1:123456789012:event-bus/loopproof-production-findings \
  -var registration_url=https://api.loopproof.ai/connector/registrations
```

The first apply creates the two parameters and stops: they hold the placeholder `unset`. Fill them with the commands
in the [README](../README.md#filling-the-parameters), then apply again with the same variables. That apply creates
the connector and registers it with LoopProof, once.

To keep an account's findings out of LoopProof, add `-var 'excluded_accounts=["111122223333"]'`; any later apply can
change the list.
