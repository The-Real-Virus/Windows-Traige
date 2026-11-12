# Windows Traige future work

## Deferred release checks

The owner approved v2.0 for release on the documented Windows 11 test scope and moved these two checks from the original weighted acceptance plan into future work.

| Check | Original weight | Work to complete |
|---|---:|---|
| Acquisition safety | 20% | In a disposable Windows lab, exercise guided offline imaging with an approved tool, a spare disk, a hardware write blocker and a separate output disk. Compare the source SHA-256 before and after acquisition, independently verify the image, and record denial, interruption, read errors and source/destination mismatch behavior. |
| Release handoff | 15% | Run the packaged GUI and CLI on the remaining Windows targets, including Windows 10 x64 and additional Windows 11 builds. Repeat the synthetic collection, five-source intake, case import and report workflows. Publish a compatibility matrix with exact builds, outcomes and package hashes. |

The weights identify the checks in the original plan. See the [v2.0 verification record](verification.md) for observed results and the [release page](https://github.com/The-Real-Virus/Windows-Traige/releases/tag/v2.0) for the portable package.

## Acquisition workflow for future validation

The approved implementation scope uses offline disk imaging guidance and intake of existing memory captures. This document retains the wider acquisition workflow for future review. A live memory acquisition adapter would need its own scope, impact assessment and validation.

v2.0 preserves bounded Windows collections, saved EVTX logs, and supported disk, memory, endpoint, identity and network originals. The workflow below covers future acquisition validation and additional adapters. Each proposed adapter needs separate review and acceptance.

## 1. Authorize and prepare the case

1. Record the case ID, owner, authority, scope, affected device identifiers, time range and approved collection operators. Record who can approve interruption, isolation and privileged access.
2. Record the target operating system, local time, UTC offset and any known clock discrepancy. Identify volatile sources and decide whether to acquire them before power state or network changes. Coordinate that decision with the incident lead.
3. Choose a private, access-controlled local evidence destination on independent storage with sufficient free space. Estimate space for the capture, retained original and working copy. Record the storage identity and encryption arrangements. Keep evidence access and encryption credentials in the organization's authorized systems.
4. Review the intended data categories, tool, version, source, destination, estimated output and expected side effects. Require separate operator approval for starting any acquisition that needs administrator access or changes the live host. Keep an offline path for imports and verification.

## 2. Import existing acquisitions first

1. Accept explicitly supported disk-image and memory-capture formats from established tools. Start with read-only format identification and preservation. Add support for segmented images only when the complete segment set, ordering and integrity can be verified. Preserve vendor manifests and tool logs alongside the original bytes.
2. Record the operator, source device and identifiers, acquisition method, tool and version, start and end times, timezone, supplied checksums and any reported read errors. Record who handed over the evidence and when. Distinguish information supplied by the source operator from values measured at intake.
3. Verify the original byte count and SHA-256 against an independently provided value when available. Report whether the value matched, was missing, or mismatched. Preserve a copy in a write-restricted evidence store and verify it again after copying. Keep a separate manifest for image segments and keep derived indexes and reports outside the originals.
4. Reject unsupported or malformed formats with an explanation. Preserve the operator's original files in place if intake fails. Detect duplicates by the original content identity and keep distinct acquisition or transfer records when appropriate. Treat untrusted files as data throughout import, indexing and export.
5. Add independent evidence adapters for approved endpoint, identity or network exports only after confirming their schema and timing semantics. Preserve each original export, record its sensor and collection window, and retain record references and parser version in the derived timeline. Indicate missing sensors and incomplete coverage separately.

## 3. Plan disk acquisition

1. Prefer offline acquisition of the authorized disk on an approved workstation with verified hardware write protection when feasible. A responder should decide whether encrypted or inaccessible volumes require an approved live workflow and document the chosen method and its effects. Keep acquisition and verification read-only toward the source.
2. Display the source device identifier, model, reported size, sector size and approved output destination. Require the operator to confirm the source and destination. Verify source and destination are on different devices before acquiring.
3. Use an approved, signed imaging tool or adapter with a documented compatibility range. Record tool and version, image format, source geometry, start and stop times, and read errors with affected ranges. Preserve the tool log and explicitly label partial output.
4. Compute streaming SHA-256 while writing, then verify the completed output in a separate pass. Record hashes for every segment and the whole-image logical checksum when supported by the format. Document how the receiving analyst can reproduce verification. Preserve the sealed master and open a verified working copy for read-only analysis.

## 4. Plan memory acquisition

1. Decide with the incident lead when memory is needed and whether the volatility and device impact justify a live capture. Record the operator, clock, host state, capture start and stop times, selected tool, signature verification and Windows build. Document the expected footprint of the tool and driver.
2. Use an approved acquisition tool compatible with the target build and security configuration. Treat driver or privilege failures as explicit outcomes. Export only to the approved private destination. Record dropped or unreadable ranges and interruptions.
3. Hash and verify the saved capture, then seal the original. Memory may contain credentials, keys and personal data. Restrict access, define retention, log transfers and analyze a verified working copy under case authorization.

## 5. Analyze and hand off

1. Use independent analysis tools against verified working copies. Record tool versions, settings, source SHA-256 and each derived artifact's references and output checksum. Keep source timestamps, normalized UTC and any known clock uncertainty distinguishable.
2. Correlate findings with Windows logs, endpoint telemetry, identity events and network records where available. Document evidence gaps, uncertainty, normal explanations, reviewer and next action. Preserve links from each finding to the underlying evidence.
3. Produce a custody log with item ID, original digest, actor, action, time in UTC, from and to, purpose and post-transfer verification. Preserve the inventory, tool logs, original evidence and independently obtained checksums. Limit the final report and supporting exports to their authorized recipients.

## 6. Set acceptance gates

- Use known synthetic images and memory fixtures and authorized lab Windows machines. Compare reported image size, hashes, record references and selected analysis results against an independent tool. Exercise the supported Windows and security configurations and record exact versions.
- Exercise ordinary and administrator paths, declined elevation, cancellation, disk full, access denied, destination loss, corrupt and incomplete input, missing segments, duplicate import and checksum mismatch. Confirm that a failed operation preserves the original and any previously verified case. Partial acquisitions need conspicuous status and a recorded reason. Confirm verified output remains verifiable after restart.
- Exercise large and segmented images, tool interruption, clock discrepancies, retention limits and different source and destination devices. Measure time, peak memory and free space. Choose performance targets from repeatable reference runs and record the tested hardware.
- Validate custody and access controls using synthetic sensitive data. Check that collection scope, diagnostic output, report exports and optional AI sharing respect authorization. Independently review input parsing, privilege boundaries and dependency signatures.
- Document remaining format and platform coverage and the manual fallback procedure. Require reproducible results from the packaged app, actual desktop interaction and handbook verification before presenting v2.0 for release approval.

Use established incident-response and evidence-handling procedures when reviewing the workflow. [NIST SP 800-86, Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final)
