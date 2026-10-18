# Examples

* [basic](basic/): the module call LoopProof's onboarding generates, with the ExternalId read from SSM Parameter
  Store.

```bash
cd examples/basic
terraform init
TF_VAR_registration_token=lprt_... terraform apply \
  -var region=us-east-1 \
  -var environment=production \
  -var control_plane_account_id=123456789012 \
  -var event_bus_arn=arn:aws:events:us-west-1:123456789012:event-bus/loopproof-production-findings \
  -var registration_url=https://api.loopproof.ai/connector/registrations
```

Apply again without `TF_VAR_registration_token` afterwards: the token is single-use and expires in 24 hours.

To keep an account's findings out of LoopProof, add `-var 'excluded_accounts=["111122223333"]'`; any later apply can
change the list.
