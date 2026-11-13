# False positives

Gate for automatic actions (#41). Every engine stays `alert` until it has run a full tracking window with no
false positives. Only then set its action in `[actions]`.

## How to run a window

1. Install the service with `[actions] default = "alert"` (README, "Run as a service").
2. Work normally for about two weeks: builds, games, IDEs, package installs, Windows/distro updates.
3. Review from an admin terminal: `avd detections --since 14d -c <config>`.
4. Fix each false positive with the narrowest tool that works, then add a row below:
   - wrong rule → fix or remove the rule
   - legitimately signed program → add its signer to `[trust] publishers`
   - one harmless file → `avd allow <file>` (allows that exact content, wherever it is)
   - noisy directory → `[watch] exclude` glob (last resort: every exclusion is a blind spot)

A window only says something about the rules that were loaded during it. Run a new one after adding or
updating a rule set.

## Tracking windows

| Start | End | Machine / OS | Signatures (rule set, hash list) | Detections | False positives |
|-------|-----|--------------|----------------------------------|------------|-----------------|
|       |     |              |                                  |            |                 |

## Log

| Date | Path | Engine | Rule | Why it was wrong | Fix |
|------|------|--------|------|------------------|-----|
|      |      |        |      |                  |     |

## Engine status

| Engine | Clean windows | Action set | Since |
|--------|---------------|------------|-------|
| hash   | 0             | alert      |       |
| yara   | 0             | alert      |       |
