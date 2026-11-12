# Windows Traige v2.0 local verification

Recorded 2026-11-12 on Windows 11 Pro 22H2 x64 build 22621.4317. The completed checks total 65% under the original weighted plan. The owner approved the exact v2.0 package for release on the documented scope and deferred physical acquisition safety and the remaining Windows test matrix to [Future Work](futurework.md).

## Current setup guidance build

| Artifact | SHA-256 |
|---|---|
| Approved v2.0 portable ZIP | C85916FF1937BC0600A4D2AEE9E2461407EA21BEBF583BFB0BFEEDFC47FF8F6A |
| Independent v2.0 rebuild ZIP | E8267C6EBBB707CA3421F0E0D29717699BD63F61E28D74019F78EDFC69065D1D |
| WindowsTraige.exe | 58830A05AD521A15F7C32D04B9AD443F1A2AC87268637C3E5779098F4A09ABA5 |
| WindowsTraige.Cli.exe | 5019C3310EB64EB42086F00FCA4043C573D72E259C56671F7067518ABCDA7BC9 |
| Source file manifest | 5557BF747E80CD64198664463366AE9DECE2520463DFDD9B0ECCCD1A81EFAA1D |
| Documentation.docx | 419DD60EAA0E3685D072F4F518684951E179ECE1B2CF2C2FC12896AB71AE3976 |

Both fresh builds produced matching unsigned executables and passed the extracted CLI smoke checks. The packaged CLI passed a five-source collection, preserved all five original files in one ZIP, saved a verified copy and imported an actual v1.0 fixture. All 21 source tests passed again.

A clean copy of the approved source also built on the test host with the documented public CPython 3.12.14 x64 distribution and hash-pinned wheels. The extracted portable package passed the CLI smoke suite and all 21 source tests passed. The approved release ZIP retains the hash in the table above.

The Qt dialog test saved all five synthetic source files with the optional fields blank. It verified missing-file errors, optional field help and visibility, preservation of the Quick, Standard and Extended collector choices, Cancel, and the guided offline form. The latter used synthetic values to test distinct disk IDs, required metadata, and timezone conversion. On the Windows desktop, the extracted application opened Network evidence with the file field visible and optional details hidden, expanded the examples, collapsed them, and saved a synthetic PCAPNG with just the file.

The 21-page handbook was rendered in Microsoft Word and visually reviewed. It contains a field-by-field reference for Set up and the offline disk record, examples for all five supplemental options, and control references for the main workbench screens.

## Previous local QA build

| Verified artifact | SHA-256 |
|---|---|
| Earlier local QA ZIP | 74693D4B7F30440AB8E51B0821681F6C75DB74131ABDA2B83DB54339C2712242 |
| Earlier independent rebuild ZIP | D7FC7AEE1B8652A9828D74CB40D53535EC1EC028C11D0289877EF08262DC53BF |
| WindowsTraige.exe | 64300AAF494CF84C1546799C5BF0C924F0B15ABCAF02C5E48FF91ACD8402F836 |
| WindowsTraige.Cli.exe | AF07F21A4C71A93D2510A4B1A8F5E2420F0F38274B5965ADCB85AFF9E176E8C0 |
| Source file manifest | 990677A53C8225F55ED8907FD027C5EF1166E805D682B1B20CEECE587E820BE9 |
| Documentation.docx | 92910A9596C18878B91B110BE222C8364FE1DEFFDEA5FCCA689C529EEFAFF581 |

The two fresh builds produced identical executable bytes and source manifests. Both executables are unsigned. The ZIPs and extracted file manifests passed integrity checks. Both extracted CLIs passed the standard smoke suite.

| Workflow | Observed result |
|---|---|
| Collection controls | A native Qt test configured all five selections and verified that Quick, Standard and Extended retained their original collector order. The packaged Windows desktop previewed Standard with a supplemental disk image and showed its filename and size. |
| Desktop handoff | A synthetic-only Custom collection produced a single ZIP. Open captured evidence in a case populated the ZIP and checksum. Import matched the detached digest and indexed the disk image. Save original produced a working copy with the exact input SHA-256. The rebuilt desktop reopened the case and showed Source not recorded for an unlabelled original. Evidence Summary showed one preserved disk image. |
| Supplemental intake | The packaged CLI preserved five original files byte for byte in one ZIP and indexed all five source types. The package opened an actual v1.0 synthetic bundle in the same case. PowerShell independently checked the Defender CSV and Entra JSON fields. Hash-pinned dpkt 1.9.8 independently checked packet counts, UTC timestamps, addresses and ports for PCAP and PCAPNG. |
| Large evidence | The test streamed a 4,295,032,832-byte synthetic image into a 4,295,035,945-byte ZIP64. Writing and verifying took 129.423 seconds in the source run. Case import took 74.316 seconds in the source run and 45.840 seconds on the preceding packaged build. The current packaged CLI reverified the same ZIP and detached checksum. The .NET ZIP reader confirmed the original member length. The input's bytes and modification time stayed intact. |
| Recovery | Twenty-one source tests passed. Coverage reported missing sources, a corrupt capture and checksum mismatch. Other tests exercised exact duplicate intake, repeated original deduplication, invalid ZIP64, cancellation and guided offline acquisition metadata. Simulated disk-full and cancellation during packing preserved the existing ZIP and original and cleaned temporary outputs. |
| Gemini | The current packaged CLI returned a live Gemini 3.5 Flash-Lite reply and performed approved retrieval with the exact synthetic evidence reference. The portable archive scan found no supplied key bytes or key file. |
| Handbook | The fifteen-page v2.0 handbook was rendered and reviewed in Word. It covers supplemental formats, guided offline imaging, ZIP64, case workflow and working copies. |

## Deferred checks and scope

- Acquisition safety is 20% of the approved scope. A disposable Windows lab, spare disk and verified hardware write blocker were unavailable. The app guides and records offline imaging performed with an approved external tool. The source tests checked same-device rejection and operator-reported read errors using synthetic files. Physical source-integrity comparison and interruption testing remain open.
- The release handoff is 15% of the approved scope. The package and handbook passed local checks on Windows 11 build 22621.4317. The remaining Windows compatibility matrix and final acceptance review require additional test access.
- The memory option imports existing raw dumps. The network index covers supported timestamped TCP and UDP records from Ethernet or raw IP. Unsupported packets remain in the original capture and are reflected in coverage.
- The approved v1.0 portable ZIP and staging copy retained their approved hash. The owner approved staging the exact v2.0 package for manual publication in [Windows Traige on GitHub](https://github.com/The-Real-Virus/Windows-Traige).
