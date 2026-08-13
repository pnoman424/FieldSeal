# FieldSeal

FieldSeal turns completed field work into a private, controlled report whose exact issued version can be verified on Midnight without publishing the report itself.

**Hackathon goal:** demonstrate one assignment from creation to recipient verification in under three minutes.

- [48-hour product wireframe and build board](docs/fieldseal-hackathon-wireframe.html)
- [Implementation map and verified baseline](docs/fieldseal-hackathon-implementation-map.md)
- [Midnight receipt pilot](midnight/README.md)

FieldSeal is adapted from the upstream [`Kfagermo/esense`](https://github.com/Kfagermo/esense) project. This fork preserves the original workflow and Midnight preprod pilot while adapting the product identity, terminology, and synthetic demonstration for the US market.

This repository is a public hackathon snapshot. It contains synthetic demonstration content only. Runtime databases, uploaded documents, credentials, private state, and generated contract artifacts are intentionally excluded.

## Demo path

1. A manager creates a realistic work order and assigns a team.
2. Field professionals add timestamped evidence and submit completed work.
3. A reviewer approves the exact version used to issue the report.
4. FieldSeal encrypts the report and anchors only its salted commitment.
5. A recipient receives limited access and verifies the issued version against Midnight.

The application currently supports:

- organization membership with explicit roles;
- assignment briefs and team responsibility;
- private planning and completion drafts;
- timestamped evidence with integrity commitments;
- deliberate, versioned planning and completion submissions;
- independent review gates;
- AES-256-GCM encrypted documentation packages;
- purpose-bound recipient access and revocation;
- local integrity receipts and optional Midnight anchoring;
- a public synthetic verification report.

Assignment does not imply competence, authorization, supervision, or professional responsibility. Source prompts are planning aids, not legal conclusions. Qualified people remain responsible for professional and jurisdiction-specific decisions.

## Privacy boundary

FieldSeal keeps report content, personal data, files, measurements, package manifests, and recipient permissions off-chain.

Only a salted document commitment and the minimum proof state needed for registration, verification, and revocation are eligible for the Midnight pilot. The application reports `not_submitted` until an independently verifiable transaction exists.

Production must keep `SECRET_KEY`, `ESENSE_RECEIPT_SECRET`, and `ESENSE_DOCUMENT_SECRET` stable and outside the application directory. The legacy `ESENSE_*` names remain supported for compatibility while the fork is migrated carefully. Losing the document secret makes existing encrypted packages unreadable.

## Local verification

Create a virtual environment and install the pinned requirements:

```text
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python workflow_smoke.py
```

The smoke workflow covers the provider, worker, reviewer, recipient, package, Midnight receipt, verification, access-revocation, and package-revocation lifecycle.

## Local visual QA

Run the isolated synthetic preview:

```text
.venv/bin/python visual_preview.py
```

Then open:

```text
http://127.0.0.1:5055/en/demo-report
```

The preview uses the real templates, styles, browser code, and a synthetic fixture representing a confirmed preprod anchor. It is useful for desktop/mobile and accessibility QA, but it is not evidence of a new network transaction.

## Public synthetic demonstration

`/en/demo-report` presents a fictional issued work report. Its API, `/api/public/midnight-demo`, returns fixed synthetic report content plus only the package reference, commitment, and verification state from the matching synthetic record. It must never return user, recipient, organization, credential, or arbitrary free-form database content.

Midnight branding is shown only at the anchoring and verification boundary. FieldSeal encryption and access control are application responsibilities, not services provided by Midnight.

## Midnight preprod compatibility

The current preprod worker configuration continues to use the established environment variables:

```text
ESENSE_MIDNIGHT_ENABLED
ESENSE_MIDNIGHT_NETWORK
ESENSE_MIDNIGHT_CONTRACT_ADDRESS
ESENSE_MIDNIGHT_WORKER_TOKEN
```

Do not rename or remove these variables without adding and testing backward-compatible `FIELDSEAL_*` aliases. The network must remain `preprod` for the hackathon unless the team explicitly changes that requirement.

## Production hygiene

Production secrets stay outside version control. The SQLite database and uploaded evidence live under the ignored `data/` directory. Credentials, private records, generated contract artifacts, and runtime state must not be committed.
