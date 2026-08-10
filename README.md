# Device Finder (Find My Alexa)

A private Alexa developer skill that makes a linked user's own Apple devices
play Apple's real Find My sound. Each account links its own Apple devices and
gives each one a spoken Alexa name, so one Echo can ring any of them.

The skill is invoked as **device finder**. The repository directory and the AWS
stack are still named `find-my-alexa` from the original single-phone version.

The source repository can be public, but the deployed Alexa skill and encrypted
iCloud session must remain private.

The original personal experience is:

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
automated access. Keep this as a personal/private friends experiment; do not
publish it as a public Alexa skill or public phone-finder product.

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

## Friends beta web app

`hosted/` contains the new Cloudflare control plane for the private friends
beta:

- installable PWA shell for testers;
- Auth0 email/password sign-in;
- invite-only account creation;
- D1-backed accounts, invites, Alexa links, device state, setup sessions, ring
  jobs, push subscriptions, and renewal alerts;
- owner admin at `/admin`;
- runner-facing APIs for queued ring jobs and Find My session-health events.
- signed AWS SQS dispatch for ring and daily no-ring health-check jobs;
- a separate AWS setup queue/worker for phone-first Apple login, 2FA, device
  selection, one test ring, and encrypted session upload;
- PWA push delivery for renewal alerts with Cloudflare Email fallback.

The hosted app does not replace the Python Find My runner yet. The runner remains
the safest v1 place for `pyicloud` because it already works with the encrypted
session bundle format. Cloudflare owns the friendly setup, account, status, and
notification surface; the Python runner owns the Apple side effect.

### Hosted commands

```sh
cd hosted
cp wrangler.example.jsonc wrangler.jsonc
npm install
npm run types
npm run migrate:local
npm run dev
```

`hosted/wrangler.jsonc` holds deployment-specific values (account IDs, queue
URLs, bucket and database names), so it is gitignored like
`skill-package/skill.json`. Copy the example and replace every `YOUR_` value.

Before production deployment:

1. Create separate Auth0 app/API clients and a dedicated database connection
   for Find My Friends.
2. Create a separate Cloudflare D1 database and replace the `database_id` in
   `hosted/wrangler.jsonc`.
3. Create Web Push VAPID keys and set `VAPID_PUBLIC_KEY` plus
   `VAPID_PRIVATE_KEY`.
4. Enable Cloudflare Email Sending for the sending domain, then set
   `EMAIL_FROM`.
5. Set these Cloudflare secrets: `RUNNER_API_TOKEN`,
   `RUNNER_AWS_ACCESS_KEY_ID`, `RUNNER_AWS_SECRET_ACCESS_KEY`, and
   `VAPID_PRIVATE_KEY`. Set `RUNNER_QUEUE_URL`, `SETUP_QUEUE_URL`, and
   `SESSION_BUCKET` from the AWS stack outputs.
6. Replace `PUBLIC_BASE_URL` with the deployed URL.
7. Apply remote migrations with `npm run migrate:remote`.
8. Deploy with `npm run deploy`.

The AWS runner stack now also accepts:

- `FindMyApiBaseUrl`: the deployed Cloudflare app URL. The Alexa skill uses this
  for account-linked users.
- `RunnerApiToken`: the same bearer secret as Cloudflare's `RUNNER_API_TOKEN`.
  The Python runner uses it when reporting health or renewal-required events
  back to Cloudflare.

The Alexa skill should be configured with Auth0 account linking for the hosted
Find My Friends app. Once linked, Alexa sends the user's Auth0 access token to
the skill Lambda; the Lambda posts to the hosted app, which queues that friend's
own iPhone job. Find My uses the dedicated `Find-My-Users` Auth0 database;
Soundbox credentials and Google login are not enabled for either Find My client.
Find My sign-up also requires a distinct username so password-manager entries
remain recognizable even though Auth0 administration uses the same tenant.
When hosted mode is configured, missing or expired account linking never falls
back to the legacy single-user phone.

The setup UI is intentionally phone-first. The Apple password passes through
the Cloudflare Worker over TLS into an encrypted AWS setup queue for the live
setup attempt. It is not stored in D1, written to logs, or retained after the
queue message is processed. The setup worker waits for the
verification code and device selection through Cloudflare, sends one test ring,
then uploads only the encrypted session bundle and selected device ID.

Daily health checks use the Python runner's no-ring validation path. They verify
that the saved Find My session can still see the selected iPhone and report
`reauthentication_required` without playing a sound.

The skill does not store an Apple password. `scripts/authenticate.py` asks for
it locally, completes Apple 2FA, and uploads one encrypted-at-rest ZIP containing
only the resulting session, cookie file, and selected device's internal
identifier to the private S3 bucket. When that session expires, rerun the script.

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
2. Skill name: `Device Finder`. The interaction model's invocation name is
   `device finder`, so anything else makes the spoken phrases below fail.
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
for the first deployment. Preserve the literal double quotes shown below:
SAM parses the parameter list a second time, and the inner quotes protect
values containing spaces or apostrophes.

```sh
sam deploy \
  --template-file .aws-sam/build/template.yaml \
  --stack-name find-my-alexa \
  --region eu-west-1 \
  --capabilities CAPABILITY_IAM \
  --resolve-s3 \
  --parameter-overrides \
    AppleId=\"YOUR_APPLE_ACCOUNT_EMAIL\" \
    DeviceName=\"Basil’s iPhone\" \
    SkillId=\"amzn1.ask.skill.REPLACE_ME\" \
    SpokenPhoneName=\"Basil's phone\"
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

If multiple devices have the same name, the script shows safe model and battery
details. It uploads the selection only after you confirm that the intended
device rang. The three session components are uploaded as one object, so a
failed upload cannot leave a mismatched session and cookie pair.

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
3. Enable **Device Finder** if it is not already enabled.
4. Make sure the Alexa app and target Echo use English (UK).
5. Complete account linking when the Alexa app prompts for it. Without a linked
   account the skill has no access token, so it answers "Please link your Alexa
   account to Device Finder" and never queues a ring. See
   [Account linking](#account-linking).
6. Say:

   > Alexa, open Device Finder.

Alexa should acknowledge immediately. The iPhone should begin its Find My alert
after the queued worker runs.

You can also test the intent directly:

> Alexa, ask Device Finder to ring my phone.

## 6. Create “Alexa, where's Basil's phone?”

The skill's default launch action rings the phone. An unpublished development
skill might not appear under **Skills → Your Skills** in the Routine editor, so
use a Custom action that issues the normal launch command:

1. Open **Alexa app → More → Routines → +**.
2. Name: `Where is Basil's phone`.
3. Under **When**, choose **Voice**.
4. Enter: `where is Basil's phone`
5. Under **Alexa Will**, choose **Custom**.
6. Enter: `ask Device Finder to ring my phone` without the `Alexa` wake word.
   Use the device's Alexa name from the web app to ring a specific one.
7. Preview the action if the app offers that option.
8. If requested, choose the Echo that should answer, then save.

Keep the Custom action last so another action cannot overlap the skill launch.

Now say:

> Alexa, where's Basil's phone?

## Account linking

Hosted mode carries no fallback: without account linking the skill has no
access token, so it never reaches the Cloudflare app and never queues a ring.
The Alexa app shows this as a "link your account" card; the Echo says "Please
link your Alexa account to Device Finder".

Alexa uses the authorization code grant and sends a client secret, so it needs
its **own Auth0 application**. The web app's client is a public single-page
app with no secret and cannot be reused here.

1. In Auth0, create a **Regular Web Application** named `Device Finder Alexa`.
2. In the Alexa Developer Console, open **Build → Account Linking** and choose
   **Auth Code Grant**, then fill in:

   | Field | Value |
   | --- | --- |
   | Authorization URI | `https://YOUR_AUTH0_DOMAIN/authorize` |
   | Access Token URI | `https://YOUR_AUTH0_DOMAIN/oauth/token` |
   | Client ID | the new Auth0 application's client ID |
   | Client Secret | the new Auth0 application's client secret |
   | Scope | `openid`, `profile`, `email`, `offline_access` |

3. Under **Domain List**, add your Auth0 domain.
4. Add a custom query parameter to the authorization URI:
   `audience=https://find-my-friends-api`. **This step is not optional.**
   Without an audience Auth0 returns an opaque access token instead of a JWT,
   and the Worker rejects it with 401 on every ring.
5. Copy the three redirect URLs Alexa lists at the bottom of the page into the
   Auth0 application's **Allowed Callback URLs**.
6. Enable **offline_access** in the Auth0 API settings so Alexa can refresh the
   token; otherwise linking silently lapses and rings start failing again.
7. In the Alexa app, open the skill and select **Link Account**.

Confirm it worked by checking that `alexa_links.status` is `linked` for the
account — a ring arriving with a linked token is the only thing that sets it:

```sh
cd hosted && npx wrangler d1 execute find-my-friends-prod --remote \
  --command "SELECT status, linked_at FROM alexa_links"
```

## Unattended renewal (opt-in)

Apple stops trusting a saved Find My session after roughly a week, which
normally means renewing by hand that often. An account can tick **Keep my Apple
password** during setup to avoid most of those renewals.

What that changes:

- the setup worker writes the password to SSM Parameter Store as a
  `SecureString` at `/find-my/{accountId}/apple-password`, only after a test
  ring was confirmed, so an abandoned setup stores nothing;
- when a session expires, the ring worker fetches it and calls
  `authenticate()`. pyicloud sends the trust token Apple issued during setup
  alongside the password, so Apple skips the verification code;
- the password is read **only after a session has already failed**, so accounts
  that never opted in cause no lookup at all.

It raises the ceiling rather than removing it. When the trust token expires
Apple asks for a verification code again, `requires_2fa` comes back true, and
the usual `reauthentication_required` alert reaches the account owner.

The box is **off by default and per account**. Invited testers are never opted
in by a choice the owner made for their own account. IAM keeps the split: the
setup worker may only `PutParameter` and the ring worker only `GetParameter`,
both scoped to `/find-my/*`.

## Session renewal

Apple decides when trusted sessions expire. If Alexa acknowledges but the phone
does not ring:

1. Inspect the `RingWorkerFunction` CloudWatch log. Errors intentionally contain
   no Apple IDs, device IDs, locations, cookies, passwords, or raw Apple
   responses. Each failure logs its category and the exception class name, for
   example `operation_failed (PyiCloudNoDevicesException)`. The class name is
   the only clue to what the catch-all category was, and it is safe to log.
2. Check the `DeadLetterAlarmName` and `DeadLetterQueueUrl` stack outputs for a
   failed request. The alarm changes state when a request reaches the queue; add
   an SNS notification action in AWS if you want email or push notification.
   **The alarm only re-fires after the dead-letter queue is emptied** — while
   messages remain it stays latched in `ALARM` and reports nothing new.
3. Rerun step 4 to replace the session in S3.

No AWS redeployment is needed for session renewal.

## Security properties

- The Apple password and 2FA code never enter Alexa. During phone setup they
  pass through the authenticated Cloudflare app to the encrypted AWS setup
  relay, are excluded from logs, and are discarded after that attempt.
- The session bucket blocks public access, uses server-side encryption and
  versioning, and is retained if the stack is deleted. Superseded session
  versions expire after one day.
- Only the worker Lambda role can read and update the session bucket.
- Only the skill Lambda can send ring messages.
- The skill Lambda validates the exact Alexa skill ID.
- Device selection is a locally confirmed, encrypted device-ID allowlist, not
  a spoken slot. Duplicate Find My names are supported.
- The worker never automatically authenticates with a stored password.
- Apple HTTP requests have connect/read limits and a total deadline that leaves
  time for cleanup before Lambda's hard timeout.
- The pyicloud background refresh monitor is stopped before the worker returns,
  preventing activity from leaking into later warm Lambda invocations.
- The worker deletes downloaded session material from Lambda `/tmp` after every
  attempt, including failures.
- Session refreshes replace one versioned S3 bundle atomically. Deployments from
  before this format are migrated after their next successful ring.
- The FIFO queue uses one message group, avoiding concurrent writes to the
  session without reserving account-wide Lambda capacity. Its visibility
  timeout exceeds six times the worker timeout to avoid premature redelivery.

SQS delivery and Apple's sound request cannot form one transaction. If Apple
accepts the sound but the network response is lost, SQS may retry and the phone
may ring twice. This is preferable here to silently losing transient requests.

The retained S3 session is sensitive. If this experiment is retired, empty and
delete the session bucket manually after deleting the stack.

## Local tests

The unit tests do not contact Apple, Alexa, or AWS:

```sh
python3 -m unittest discover -s tests -v
sam validate --lint --template-file template.yaml
sam build --template-file template.yaml
```
