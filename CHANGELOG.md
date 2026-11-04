# Changelog

All notable changes to this project will be documented in this file.

## [1.3.0] - 2026-11-04

### Bug Fixes

- Count a rule's length in UTF-16 code units, as SSM does

### Documentation

- Accepting risks in the README: what a rule holds, its register entry, when LoopProof reads it, what it refuses (IH-60)
- Accept_rules in the configuration, architecture, security, examples, troubleshooting and upgrading pages (IH-60)
- The example passes accept_rules through and outputs the rules' path (IH-60)
- CLAUDE.md's contract holds accept_rules, its output and the parameters' path, name and value (IH-60)
- Say how the 4096 characters are counted
- The two inputs in the README, CLAUDE.md, docs and the example
- README's provider range again, and lines within 120 characters

### Features

- Add accept_rules, each rule's shape checked at plan, naming the input and the rule's id (IH-60)
- Publish each accept rule as its own String parameter under /loopproof/<environment>/accept-rules (IH-60)
- The connector role may read the accept rules by path and by name, and nothing else new (IH-60)
- Add the accept_rules_parameter_path output (IH-60)
- One input per kind, threat_accept_rules and vulnerability_accept_rules

### Testing

- Pass accept_rules through the test roots, with sample rules and the published value's contract (IH-60)
- A rule of the wrong shape fails the plan, naming accept_rules and the rule's id only (IH-60)
- Each rule is its own parameter, the same bytes every time, read by path as the connector role (IH-60)
- With no rule nothing is published and the read returns none; the upgrade from 1.2.0 adds only the read (IH-60)
- The leak check ignores what the message and the named ids hold by chance (IH-60)
- Count a rule's length as SSM does
- The leak check reads the diagnostics alone
- One input per kind, threat_accept_rules and vulnerability_accept_rules

## [1.2.0] - 2026-10-28

### Documentation

- The rule forwards GuardDuty's findings at every severity, why, and the upgrade from 1.1.0 (IH-65)
- The upgrade from 1.1.0 shows the forwarder role's trust policy as known after apply, and why (IH-65)
- Keep CLAUDE.md's new lines within 120 characters (IH-65, review round 1)

### Features

- Forward GuardDuty's findings at every severity, and the other products' by severities, in the one rule (IH-65)

### Testing

- GuardDuty's findings are forwarded at every severity, the other products' by severities, and an excluded account's never (IH-65)
- The upgrade from 1.1.0 changes the rule's pattern and description in place, and nothing else (IH-65)
- The upgrade's plan reads the forwarder role's trust policy again at apply, and the apply leaves it as it was (IH-65)

## [1.1.0] - 2026-10-27

### Bug Fixes

- The connector role's description names the tag reads, and that an aggregator query returns any configuration (IH-120)

### Documentation

- The connector role's tag reads, the aggregator input, its permissions and the upgrade from 1.0.1 (IH-120)
- The aggregator grant covers every aggregator of the account and Region, with nothing to set (IH-120)
- An aggregator query returns any configuration, not only tags, wherever the role's reads are listed (IH-120)

### Features

- The connector role reads ECR repositories' tags, and Control Tower's Config aggregator when asked (IH-120)
- Query every Config aggregator of the account in the module's Region, without an input or a lookup (IH-120)

### Testing

- The connector role reads repositories' tags, queries Control Tower's aggregator when asked, and upgrades from 1.0.1 adding only that (IH-120)
- A missing aggregator fails the plan with the provider's "couldn't find resource" (IH-120)
- Retry a new probe role's InvalidClientTokenId in the tag reads, as IAM settles (IH-120)
- The connector role queries any Config aggregator of its account and Region, with no input (IH-120)
- The stand-in aggregator never takes Control Tower's name, and the upgrade updates the role's description (IH-120)
- Wait until STS accepts a new probe role's credentials before a test uses them (IH-120)
- ConnectorProbe retries InvalidClientTokenId for two minutes, wherever a test assumes through it (IH-120)
- Keep the ExternalId out of an upgrade assertion's message, and give REPOSITORY_TAG its comment (IH-120)

## [1.0.1] - 2026-10-25

### Bug Fixes

- Register.sh names Settings for a new token, and offers the paste only before the proof (IH-116, slice 2)

### Documentation

- README and the paste outputs say where a new token comes from, and paste only before the proof (IH-116, slice 2)
- Security, getting started, troubleshooting, configuration, architecture and upgrading follow the messages (IH-116, slice 2)
- Register with a new token within its 24 hours (IH-116, slice 2, review round 1)

### Testing

- Register.sh says where a new token comes from, and pastes only before the proof (IH-116, slice 2)
- The registration's integration tests check the new words, through Terraform (IH-116, slice 2)

## [1.0.0] - 2026-10-24

### Bug Fixes

- Wrap the refusal message, and count an empty curl status as no answer
- Refuse a curl older than 7.76.0 before the call, with a plain message

### Documentation

- The two-part install, the fill commands, permissions, the tainted retry and upgrading
- CLAUDE.md's interface contract, credentials and testing for the parameters
- Keep the spent token, upgrade with the install token, curl 7.76.0, saved plans, quiet rotation
- Say a lost registration token comes from LoopProof, not when LoopProof issues one

### Features

- Read the ExternalIds and the registration token from SSM, and register once at apply

### Testing

- Install the connector from two SSM parameters and count the registration calls

## [0.3.0] - 2026-10-18

### Features

- Add excluded_accounts, filtered at the edge and published in SSM

## [0.2.0] - 2026-10-16

### Features

- Report the Region in the connector registration

## [0.1.0] - 2026-10-11

### Bug Fixes

- Hook permissions

### Documentation

- Document how long an ExternalId rotation takes to apply
- Show provider version ranges in the README

### Features

- Add the LoopProof connector module

### Testing

- Hold each rotation step until IAM has settled

### Ci

- Add Terraform CI/CD workflows, Makefile and requirements

<!-- generated by git-cliff -->
