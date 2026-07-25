# Alexa → Apple Find My feasibility

Research date: 25 July 2026

## Bottom line

There are two materially different targets:

1. **iPhone, iPad, Mac, Apple Watch, AirPods, and supported Beats:** a personal Alexa skill can probably ring these from a cloud-hosted Lambda, but only by calling Apple's undocumented iCloud web API. This is technically demonstrated by current open-source software, not officially supported by Apple, and liable to break.
2. **AirTags and other Find My “Items”:** they cannot be rung by a cloud-only Alexa skill. Apple exposes no public API for Find My items, and iCloud.com's documented Play Sound feature explicitly lists devices, AirPods, and Beats—not AirTags. AirTag sound is available from the Find My app or Siri when the item is nearby.

If AirTag support is essential, the supported voice solution is Siri (for example, a HomePod mini). An Alexa solution would need an always-on Apple device acting as a local bridge and would still rely on brittle UI automation.

## What is officially available

Apple documents iCloud.com Play Sound for iPhone, iPad, iPod touch, Mac, Apple Watch, AirPods, and supported Beats. It works through Silent mode and, if the device is offline, remains pending until the device reconnects:

- [Apple: Play a sound with Find Devices on iCloud.com](https://support.apple.com/en-mide/guide/icloud/mmfc0f19b5/icloud)

AirTags are deliberately treated as **Items**, not Devices. Apple documents Play Sound in the Find My app only when the AirTag is nearby:

- [Apple: Locate an AirTag or other item](https://support.apple.com/en-asia/guide/iphone/ipha779f0c10/ios)
- [Apple: Play a sound on an item from a Mac](https://support.apple.com/en-ie/guide/findmy-mac/fmm18ab2a56c/mac)

Apple supports the desired AirTag voice experience through Siri:

- [Apple AirTag: “Hey Siri, find my wallet”](https://www.apple.com/kz/airtag/)
- [Apple HomePod mini: ping devices or AirTag items](https://www.apple.com/homepod-mini/)

Apple's developer-facing Find My program is for manufacturers enrolling accessories in the Find My network via MFi. It is not an owner API for reading items or making an AirTag sound:

- [Apple Developer: Find My network](https://developer.apple.com/find-my/)

## Cloud-only Alexa skill for iPhones

### Technically feasible

A custom Alexa skill can run in AWS Lambda. Alexa-hosted skills provision Lambda, DynamoDB, S3, and a code repository:

- [Amazon: Host a custom skill in Lambda](https://developer.amazon.com/en-US/docs/alexa/custom-skills/host-a-custom-skill-as-an-aws-lambda-function.html)
- [Amazon: Alexa-hosted resources and limits](https://developer.amazon.com/en-US/docs/alexa/hosted-skills/usage-limits.html)

The current `pyicloud` 2.6.5 library implements the undocumented Find My iPhone web endpoint, including `play_sound()`. It was released on 9 June 2026 and explicitly warns that authentication expires:

- [PyPI: pyicloud 2.6.5 and Play Sound](https://pypi.org/project/pyicloud/)
- [pyicloud Find My iPhone implementation](https://raw.githubusercontent.com/picklepete/pyicloud/master/pyicloud/services/findmyiphone.py)

Home Assistant 2026.7.4 uses the same library version and exposes `icloud.play_sound`, which is useful evidence that the device path is still in active use:

- [Home Assistant: Apple iCloud integration](https://www.home-assistant.io/integrations/icloud/)
- [Home Assistant iCloud dependency manifest](https://raw.githubusercontent.com/home-assistant/core/dev/homeassistant/components/icloud/manifest.json)

### Not an official or durable integration

Apple publishes no Find My owner API. `pyicloud` reproduces Apple's private web calls. Apple can change authentication or the endpoint without notice. This has happened before.

More importantly, Apple's current iCloud terms prohibit accessing the service through automated means such as scripts. A Lambda that calls the private endpoint is therefore not a clean, supported integration:

- [Apple iCloud Terms, section on prohibited automated access](https://www.apple.com/legal/internet-services/icloud/en/terms.html)

This makes the approach reasonable only as an informed, personal experiment—not something to publish in the Alexa Skill Store or promise as maintenance-free.

## Recommended implementation if accepting the private-API risk

Use a **personal AWS account**, even though the interaction is still an Alexa skill:

```text
“Alexa, ask Device Finder to ring my iPhone”
                    │
                    ▼
        private Alexa Custom Skill
                    │
                    ▼
       fast Lambda in eu-west-1
                    │
                    ▼
            encrypted FIFO SQS
                    │
                    ▼
      worker Lambda using pyicloud
                    │
                    ├── encrypted S3: atomic session bundle
                    ├── encrypted selected device ID
                    └── Find My play_sound()
```

The Apple password and 2FA code should be entered only into a local setup
utility. Upload the resulting trusted session, not the password. The queue lets
Alexa respond within its deadline while the slower iCloud request runs in the
background.

Why not put everything in the simplified Alexa-hosted resources? Personal AWS
resources make it easier to provision a private encrypted session bucket, a
FIFO worker queue, explicit IAM policies, and lifecycle controls:

- [Amazon: Use personal AWS resources with an Alexa-hosted skill](https://www.developer.amazon.com/en-US/docs/alexa/hosted-skills/alexa-hosted-skills-personal-aws.html)

An app-specific Apple password is preferable during local setup if Find My
accepts it. Apple lets it be revoked independently, though changing the primary
password revokes all app-specific passwords:

- [Apple: App-specific passwords](https://support.apple.com/en-ie/102654)

Implementation requirements:

- Select one exact device locally and encrypt its stable device ID in S3.
- Store no Apple password in AWS.
- Never log credentials, cookies, device IDs, locations, or raw iCloud responses.
- Stop pyicloud's background Find My monitor before the worker returns, and
  bound Apple HTTP calls below the Lambda timeout.
- Persist the session, cookies, and device selection as one atomic S3 object.
- Queue iCloud work so Alexa can answer within its response deadline.
- If authentication expires, fail safely and require local reauthentication. Never request an Apple password or 2FA code by voice.
- Restrict the Lambda permission to the exact Alexa Skill ID.
- Use a dedicated Apple Account if practical, with Family Sharing access only to the device(s) that must ring, to reduce blast radius.
- Treat AirPods/Beats as test-dependent even though Apple supports them on iCloud.com; device results returned by the private API can vary.

Alexa's response deadline is documented here:

- [Amazon: Progressive responses and the eight-second deadline](https://www.developer.amazon.com/en-US/docs/alexa/custom-skills/progressive-response-api-reference.html)

## Natural command wording

A development skill can be enabled on Echo devices registered to the same Amazon developer account. The reliable built-in invocation form is:

> Alexa, ask Device Finder to ring my iPhone.

- [Amazon: Test a development skill on an Alexa device](https://www.developer.amazon.com/en-US/docs/alexa/test/test-your-skill-overview.html)

A routine can provide a shorter phrase, but Amazon's custom-task route has an important limitation omitted from the earlier discussion: the skill must have been published to the live stage at least once before a development-stage custom task can be tested in routines. Custom tasks in routines are also still beta:

- [Amazon: Test a custom task with Alexa Routines](https://developer.amazon.com/en-GB/docs/alexa/custom-skills/test-custom-task-with-alexa-routines.html)
- [Amazon: Integrate a custom task with Alexa Routines](https://developer.amazon.com/en-US/docs/alexa/custom-skills/integrate-custom-task-with-alexa-routines.html)

Therefore, version 1 should use the explicit “ask Device Finder…” invocation and avoid making routine support a dependency.

## AirTag options

| Option | AirTags | iPhone in Silent mode | Always-on hardware | Reliability |
|---|---:|---:|---:|---|
| Alexa skill → private iCloud API | No | Yes | No | Medium/fragile |
| Alexa skill → local Mac bridge → Find My UI | Yes, when nearby | Yes | Mac | Low/fragile |
| Siri/HomePod | Yes, when nearby | Yes | HomePod/Apple device | High/supported |
| Alexa calls the phone | No | Usually no | No | Medium |
| Replace tags with Alexa-supported trackers | Yes, for replacement tags | N/A | No | Depends on brand/region |

The only plausible AirTag bridge while retaining Alexa is:

```text
Alexa skill → signed command queue → always-on Mac
                                      → Find My.app UI automation
                                      → nearby AirTag
```

The Mac already holds the Apple Account in its Keychain, so the cloud would not need Apple credentials. However, Find My has no documented AppleScript or Shortcuts action for Play Sound. The bridge would need Accessibility/UI scripting, would depend on macOS language and layout, and could break after OS updates. It also cannot ring an AirTag outside Bluetooth reach of an owner-authorized Apple device.

This should be treated as an optional laboratory prototype, not the core design.

## Recommendation

1. Build a small proof of concept for **one iPhone only**, with the explicit invocation phrase and personal AWS security controls.
2. Before building the full skill, run `pyicloud 2.6.5` locally against a dedicated/app-specific credential and confirm that the account authenticates, lists the intended iPhone, and plays a sound. This avoids deploying an architecture around an Apple-account-specific authentication failure.
3. Decide separately whether AirTag voice control is valuable enough to use Siri/HomePod. Do not make AirTags a promised feature of the cloud skill.
4. If Alexa is non-negotiable for AirTags and an always-on Mac is available, prototype the Mac UI bridge after the iPhone proof of concept.
