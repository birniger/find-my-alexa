# Find My Alexa

A private Alexa developer skill that makes one configured iPhone play Apple's
real Find My sound.

The source repository can be public, but the deployed Alexa skill and encrypted
iCloud session must remain private.

The intended experience is:

> **You:** Alexa, where's Basil's phone?
>
> **Alexa:** Okay, ringing Basil's phone.
>
> **iPhone:** plays the Find My alert, including in Silent mode.

The short phrase is an Alexa Routine that launches the private skill. Launching
the skill queues a ring request; an AWS worker then uses a locally-created,
trusted iCloud session to call Find My.

## Important boundary

Apple does not publish a Find My owner API. This project uses the undocumented
iCloud web endpoint implemented by `pyicloud`. It can stop working when Apple
changes authentication or the service. Apple's iCloud terms also restrict
automated access. Keep this as a personal, private experiment; do not publish it
as a public Alexa skill.

See [RESEARCH.md](RESEARCH.md) for the source-backed feasibility review.

## Architecture

```text
Alexa Routine: “where's Basil's phone?”
                      │
                      ▼
       private Alexa Custom Skill
                      │
                      ▼
        fast Lambda → encrypted SQS queue
                              │
                              ▼
                    worker Lambda (pyicloud)
                              │
                    encrypted S3 session
                              │
                              ▼
                   Apple Find My Play Sound
```

The skill does not store an Apple password. `scripts/authenticate.py` asks for
it locally, completes Apple 2FA, and uploads only the resulting session,
cookie files, and the selected device's internal identifier to the private S3
bucket. When that session expires, rerun the script.

## Prerequisites

- An Amazon developer account used by the target Echo/Alexa account.
- A personal AWS account.
- AWS credentials configured locally for the account.
- [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html).
- Python 3.13 or later locally.
- The exact iPhone name shown in **Find My → Devices**.

Use AWS region `eu-west-1` for an Alexa account in Switzerland/Europe.

## 1. Deploy the AWS backend once

The first deployment creates the backend and produces the Lambda ARN needed
when creating the Alexa skill. Leave `SkillId` empty. This temporarily permits
Alexa endpoint validation, while the handler itself rejects every request
until the exact skill ID is installed in step 3.

```sh
sam build
sam deploy --guided \
  --stack-name find-my-alexa \
  --region eu-west-1
```

Use these parameter values when prompted:

```text
AppleId: your Apple Account email
DeviceName: the exact Find My name, for example Basil’s iPhone
SkillId: leave empty
SpokenPhoneName: Basil's phone
Allow SAM CLI IAM role creation: Y
Save arguments to configuration file: Y
```

Record the `SkillFunctionArn` and `SessionBucketName` stack outputs.

## 2. Create the private Alexa developer skill

In the [Alexa Developer Console](https://developer.amazon.com/alexa/console/ask):

1. Select **Create Skill**.
2. Skill name: `Basil Phone Finder`.
3. Primary locale: **English (UK)**. The Echo/Alexa app locale must match.
4. Experience/model: **Custom**.
5. Hosting: **Provision your own**.
6. Start from scratch.
7. Under **Build → JSON Editor**, paste
   [`skill-package/interactionModels/custom/en-GB.json`](skill-package/interactionModels/custom/en-GB.json).
8. Select **Save Model**, then **Build Model**.
9. Under **Endpoint**, select **AWS Lambda ARN**.
10. Paste the `SkillFunctionArn` into **Default Region**, then save.
11. Copy the skill ID from the console. It starts with `amzn1.ask.skill.`.

This remains a development skill. It does not need Skill Store publication.

CLI users can copy
[`skill-package/skill.example.json`](skill-package/skill.example.json) to the
gitignored `skill-package/skill.json`, then replace `YOUR_ALEXA_VENDOR_ID` and
`YOUR_SKILL_FUNCTION_ARN`.

## 3. Lock Lambda to the skill ID

Redeploy with the exact skill ID. Keep the same Apple ID and device name used
for the first deployment:

```sh
sam deploy \
  --stack-name find-my-alexa \
  --region eu-west-1 \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    AppleId='YOUR_APPLE_ACCOUNT_EMAIL' \
    DeviceName='Basil’s iPhone' \
    SkillId='amzn1.ask.skill.REPLACE_ME' \
    SpokenPhoneName="Basil's phone"
```

This adds the Lambda resource permission for that one Alexa skill and makes the
handler reject any mismatched skill ID.

## 4. Create and upload the trusted Apple session

Create a local virtual environment:

```sh
python3 -m venv .venv
.venv/bin/pip install -r scripts/requirements.txt
```

Authenticate, verify the configured name, and make the phone ring once as an
end-to-end Apple test:

```sh
.venv/bin/python scripts/authenticate.py \
  --apple-id 'YOUR_APPLE_ACCOUNT_EMAIL' \
  --stack-name find-my-alexa \
  --region eu-west-1 \
  --device-name 'Basil’s iPhone' \
  --test-ring
```

Start with an Apple app-specific password. If Apple rejects it for Find My, the
undocumented endpoint may require the primary Apple Account password. In either
case, the password is held only in that process and is not written or uploaded
by this project. The script prints device names, but never IDs or locations.

The script requests an Apple 2FA challenge and securely hides both password and
verification-code input. Accounts that require a physical security key need
manual adaptation and are intentionally rejected by this setup flow.

## 5. Enable and test the development skill

1. In the Alexa Developer Console, open **Test** and enable testing for
   **Development**.
2. In the Alexa app signed into the same Amazon account, go to
   **More → Skills & Games → Your Skills → Dev**.
3. Enable **Basil Phone Finder** if it is not already enabled.
4. Make sure the Alexa app and target Echo use English (UK).
5. Say:

   > Alexa, open Basil Phone Finder.

Alexa should acknowledge immediately. The iPhone should begin its Find My alert
after the queued worker runs.

You can also test the intent directly:

> Alexa, ask Basil Phone Finder to ring the phone.

## 6. Create “Alexa, where's Basil's phone?”

The skill's default launch action rings the phone. An unpublished development
skill might not appear under **Skills → Your Skills** in the Routine editor, so
use a Custom action that issues the normal launch command:

1. Open **Alexa app → More → Routines → +**.
2. Name: `Where is Basil's phone`.
3. Under **When**, choose **Voice**.
4. Enter: `where is Basil's phone`
5. Under **Alexa Will**, choose **Custom**.
6. Enter: `open Basil Phone Finder` without the `Alexa` wake word.
7. Preview the action if the app offers that option.
8. If requested, choose the Echo that should answer, then save.

Keep the Custom action last so another action cannot overlap the skill launch.

Now say:

> Alexa, where's Basil's phone?

## Session renewal

Apple decides when trusted sessions expire. If Alexa acknowledges but the phone
does not ring:

1. Inspect the `RingWorkerFunction` CloudWatch log. Errors intentionally contain
   no Apple IDs, device IDs, locations, cookies, or passwords.
2. Check the `DeadLetterQueueUrl` stack output for a failed request.
3. Rerun step 4 to replace the session in S3.

No AWS redeployment is needed for session renewal.

## Security properties

- The Apple password and 2FA code never enter Alexa or AWS.
- The session bucket blocks public access, uses server-side encryption and
  versioning, and is retained if the stack is deleted.
- Only the worker Lambda role can read and update the session bucket.
- Only the skill Lambda can send ring messages.
- The skill Lambda validates the exact Alexa skill ID.
- Device selection is a locally confirmed, encrypted device-ID allowlist, not
  a spoken slot. Duplicate Find My names are supported.
- The worker never automatically authenticates with a stored password.
- The FIFO queue uses one message group, avoiding concurrent writes to the
  session without reserving account-wide Lambda capacity.

The retained S3 session is sensitive. If this experiment is retired, empty and
delete the session bucket manually after deleting the stack.

## Local tests

The unit tests do not contact Apple, Alexa, or AWS:

```sh
python3 -m unittest discover -s tests -v
```
