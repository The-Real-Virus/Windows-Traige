"""Generate Documents/Documentation.docx using the Codex document runtime."""

from pathlib import Path
from sys import argv

from docx import Document
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor


def body(document, text, space_before=None):
    paragraph = document.add_paragraph(text)
    if space_before is not None:
        paragraph.paragraph_format.space_before = Pt(space_before)


def headings(document, title, text):
    document.add_heading(title, 2)
    body(document, text)


def code(document, commands):
    for command in commands:
        p = document.add_paragraph(style="No Spacing")
        p.paragraph_format.space_after = Pt(5)
        run = p.add_run(command)
        run.font.name = "Consolas"
        run.font.size = Pt(9)


def table(document, headers, rows, widths):
    table = document.add_table(rows=1, cols=len(headers))
    table.autofit = False
    for col, width in zip(table.columns, widths):
        col.width = Inches(width)
    properties = table._tbl.tblPr
    borders = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        element = OxmlElement("w:" + edge)
        element.set(qn("w:val"), "single")
        element.set(qn("w:color"), "D9D9D9")
        element.set(qn("w:sz"), "4")
        borders.append(element)
    properties.append(borders)
    repeat = OxmlElement("w:tblHeader")
    table.rows[0]._tr.get_or_add_trPr().append(repeat)
    for index, values in enumerate((headers, *rows)):
        cells = table.rows[0].cells if index == 0 else table.add_row().cells
        for cell, value, width in zip(cells, values, widths):
            cell.width = Inches(width)
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            p = cell.paragraphs[0]
            p.paragraph_format.space_before = Pt(5)
            p.paragraph_format.space_after = Pt(5)
            run = p.add_run(value)
            run.font.size = Pt(10)
            shade = OxmlElement("w:shd")
            shade.set(qn("w:fill"), "254568" if index == 0 else "F2F6FA" if index % 2 == 0 else "FFFFFF")
            cell._tc.get_or_add_tcPr().append(shade)
            if index == 0:
                run.bold = True
                run.font.color.rgb = RGBColor.from_string("FFFFFF")


def page(document, title):
    document.add_page_break()
    document.add_heading(title, 1)


def make(destination):
    doc = Document()
    doc.core_properties.title = "Windows Traige User Handbook"
    doc.core_properties.subject = "Collecting and investigating Windows evidence with Windows Traige v2.0"
    doc.core_properties.author = "Windows Traige"
    section = doc.sections[0]
    section.left_margin = section.right_margin = Inches(0.85)
    section.top_margin = section.bottom_margin = Inches(0.72)
    section.page_width, section.page_height = Inches(8.5), Inches(11)
    for name, size in (("Normal", 11), ("Title", 30), ("Heading 1", 22), ("Heading 2", 13)):
        style = doc.styles[name]
        style.font.name = "Aptos"
        style.font.size = Pt(size)
        style.font.color.rgb = RGBColor(0, 0, 0)
        style.paragraph_format.space_after = Pt(8)
    doc.styles["Normal"].paragraph_format.line_spacing = 1.12
    title_properties = doc.styles["Title"]._element.get_or_add_pPr()
    for border in title_properties.findall(qn("w:pBdr")):
        title_properties.remove(border)
    doc.add_paragraph("Windows Traige User Handbook", style="Title")
    body(doc, "v2.0")
    body(doc, "Windows Traige helps incident responders capture evidence from an authorized Windows host, verify its integrity, and investigate the resulting timeline in one local workspace. The desktop workbench and console program share the same evidence and case formats.")
    headings(doc, "Supported systems", "The release targets Windows 10 and 11 x64 within the pinned runtime's supported scope. Native acceptance uses Windows 11 Pro 22H2 x64, build 22621.4317. Windows 10 and other Windows 11 builds require independent verification. See the local verification record for current acceptance results.")
    headings(doc, "First launch", "Extract the complete portable ZIP to a trusted local NTFS folder. Keep the _internal and _cli_runtime folders alongside WindowsTraige.exe and WindowsTraige.Cli.exe. Start the desktop at standard privilege. The application does not require a Python or Qt installation.")
    headings(doc, "A first investigation", "Use Collection to preview an authorized capture and choose a private output directory. Open Cases and Timeline and import the resulting ZIP or an existing Windows EVTX log. Supply a separately held SHA-256 when available. Filter the timeline, open a record, add an annotation, and use Findings and Reports to export material.")
    headings(doc, "Practice with synthetic evidence", "Use the CLI fixture command to produce a sample in an existing local folder. Search for System event 7045 and inspect record 42. The fixture also includes a related process, a network observation, a reused PID, an absent Sysmon channel and a denied Security channel.")
    code(doc, [r".\WindowsTraige.Cli.exe fixture --out .\Practice"])
    headings(doc, "Choose how the workbench looks", "Use Appearance in the top-right corner. System follows Windows. Light and Dark set the workbench colors directly and are remembered. Pretty view explains evidence in ordinary text. Raw JSON shows the structured fields and original event XML where present.")

    page(doc, "Your first capture")
    headings(doc, "Prepare a destination", "Create a private folder on a local NTFS drive. Use a folder you can write to and that the authorized responders can access. A collection ZIP may contain usernames, network addresses, filenames or sensitive event text. Use a synthetic case for demonstrations.")
    headings(doc, "Choose the collection profile", "Open Collection. Start with Quick when you need recent activity and volatile context. Use Standard for an investigation that also needs Security events, Defender, PowerShell, users and startup metadata. Select Extended for the additional channels described in this guide. Use Custom when a responder has identified exact sources.")
    headings(doc, "Review the window and limits", "The event window is measured backward from the collection start. Choose a window that includes the time you are investigating. The maximum records per source bounds the capture. A source can return fewer records because the log is empty, disabled, inaccessible or its oldest records were overwritten.")
    headings(doc, "Preview and start", "Enter or browse for your output folder and click Preview scope. Confirm the proposed event window, collectors and sensitive fields. Start collection and review the confirmation. While it runs, the status identifies the current phase. Cancel operation stops finalization and preserves earlier completed bundles.")
    headings(doc, "Read the result and open the evidence", "Read Source coverage before interpreting the results. Use Open captured evidence in a case to fill the ZIP and checksum fields. Enter a new case folder inside an existing parent, then choose Verify and import. For evidence supplied by someone else, use a checksum obtained independently when available.")

    page(doc, "Add evidence to the same ZIP")
    headings(doc, "Choose optional evidence", "Start with Quick, Standard or Extended. Check the evidence you want to include, then choose Set up next to that option. For a saved file, choose Browse, select the file, and choose OK. Choose Show optional details if your IT team or responder gave you more information about the file.")
    table(doc, ("Option", "When to use it and what file to ask for"), (
        ("Disk image", "Preserve the contents of a drive so a responder can examine it later. Ask for an existing raw .dd, .img or .raw image."),
        ("Memory capture", "Preserve a snapshot of what was in a computer's memory. Ask a responder for an existing .raw or .mem dump."),
        ("Endpoint telemetry", "Review activity recorded by your organization’s endpoint security service. Ask for a Defender XDR DeviceEvents CSV with Timestamp, DeviceId, DeviceName, ActionType and ReportId."),
        ("Identity activity", "Review suspicious account sign-ins. Ask for a Microsoft Entra sign-in JSON array or a Graph export with a value array."),
        ("Network evidence", "Review connections seen by a firewall, sensor or capture tool. Ask for a .pcap or .pcapng file. Supported TCP and UDP metadata appears in the timeline."),
    ), (1.55, 5.25))
    headings(doc, "Collect and investigate", "Preview the profile and the size of the selected originals. Run the collection, then choose Open captured evidence in a case. The ZIP contains Windows data, supplemental originals, hashes and coverage. Review Coverage for each original and Evidence Summary for missing or partial sources.")
    headings(doc, "Keep evidence private", "Captures and exports may contain secrets or personal information. Keep the ZIP and detached SHA-256 in controlled storage. Select a supplemental record and choose Save original to create a checksum-verified working copy for an independent analysis tool.")

    page(doc, "What to enter in Set up")
    body(doc, "For a saved file, you can choose the file and leave the optional details blank. Use the values from the person who supplied it or from the capture report. The app records the information you supply alongside the original.")
    table(doc, ("Field", "What it means and what to enter"), (
        ("Evidence file", "Required. The saved file you want to include. Use Browse to pick it. For example, choose the office firewall capture named traffic.pcapng."),
        ("SHA-256 checksum file", "Optional. A separately supplied .sha256 or .txt file containing a fingerprint of the original. Choose it with Browse. Windows Traige computes its own fingerprint even when this field is blank."),
        ("Source or device ID", "Optional. Where the evidence came from. Examples include OFFICE-PC-07, a drive serial, your company’s Entra tenant name or the HQ firewall."),
        ("Tool and version", "Optional. The program that captured or exported the evidence and its version, such as Wireshark 4.4. Check the capture report or the tool’s About screen."),
        ("Operator", "Optional. The person who captured or exported the file. Enter their name, or your own name if you performed the capture or export."),
        ("Acquired time", "Optional. The capture or export time as recorded by the operator. Include the timezone, such as 2026-11-12T14:30:00+05:00 for 2:30 pm at UTC+05:00."),
        ("Custody notes", "Optional. One line on how you received the file, who handed it over, or any known gaps. For example, received from IT in ticket IR-024."),
    ), (1.65, 5.15))
    body(doc, "Show optional details and Hide optional details change what you see. They retain your entries. OK saves the setup for this collection. Cancel discards changes made in the dialog. If you skip setting up a checked option, it appears as unavailable in coverage.", space_before=9)

    page(doc, "Offline disk acquisition and large files")
    headings(doc, "Prepare an authorized acquisition", "A responder uses a dedicated workstation, a verified hardware write blocker, a separate output disk and an approved signed imaging tool. Record the source and output device identifiers and independently verify the completed raw image SHA-256. Preserve the imaging tool log and report read errors.")
    headings(doc, "Record the offline acquisition", "Select Disk image, choose Set up, and open Offline imaging guide and record. Follow the field reference on the next page. Return to Set up with the finished image, separately verified checksum, tool and version, operator and acquired time. Reported read errors appear as partial coverage.")
    headings(doc, "Review the evidence footprint", "On a running Windows computer, ordinary collection uses memory and can produce Windows activity records. The app reads supported evidence and writes outputs to the chosen local destination. A responder supplies existing memory dumps for intake.")
    headings(doc, "Allow enough storage", "Large originals use ZIP64 in the same evidence ZIP. Choose a local volume that supports large files and has enough space for the original, ZIP, and any working copy. Preserve the verified ZIP and its separately held SHA-256. The case folder stores its own verified ZIP copy.")
    headings(doc, "Read partial and unsupported results", "Windows Traige preserves originals and indexes the supported evidence fields. For network exports it indexes supported timestamped TCP and UDP packets. Coverage identifies skipped or limited records. The app can read prior Windows Traige v1.0 bundles.")

    page(doc, "What to enter in the offline disk record")
    body(doc, "The offline record is for the operator who used a write blocker and a separate output disk. For an image you received as a file, use the normal Disk image setup. The record captures the operator’s hardware checks.")
    table(doc, ("Field", "What to copy from the acquisition report"), (
        ("Source disk ID", "The serial number or unique label of the drive that was imaged, such as SRC-104."),
        ("Output disk ID", "The serial number or unique label of the separate drive that received the image, such as OUT-209. The two disk IDs must differ."),
        ("Write blocker ID", "The serial number or equipment label of the verified hardware device that prevented writes to the source, such as WB-12."),
        ("Source sector size in bytes", "Copy the reported sector size. The supported values are 512 and 4096."),
        ("Source size in bytes", "Copy the exact byte count shown in the acquisition report. Enter digits without commas or units."),
        ("Reported read errors", "Copy the count shown in the imaging report. Enter 0 only if the report confirms zero read errors."),
        ("Operator confirmation", "Check this only after verifying the hardware write blocker and confirming that the destination is a separate disk."),
    ), (1.75, 5.05))
    body(doc, "OK saves the offline record and opens the required details in Set up. Cancel returns with the prior record intact. Reset removes the offline record from the current setup. It leaves the image and checksum files in place.", space_before=9)

    page(doc, "Collection profiles and sources")
    body(doc, "Quick samples processes, TCP, UDP, System and Application events, host data and adapters. Standard adds the other standard event channels and the inventory and account sources below. Extended adds the operational sources on the following page. Custom accepts individual collectors and event channels. Extended and Custom support selected files and optional process command lines.")
    table(doc, ("Collector IDs", "Scope"), (
        ("processes, processes-sensitive", "Process name, PID, parent PID, creation time and executable path where available. The sensitive variant includes command lines by explicit selection."),
        ("tcp, udp, adapters", "TCP local and remote endpoints and state, UDP local endpoints, owning PID, and interface addresses."),
        ("routes, dns, dns-cache, neighbors", "Routes, resolver addresses, cached DNS entries and neighbor IP and link-layer metadata."),
        ("events-system, events-application, events-security, events-defender, events-powershell, events-sysmon", "System, Application, Security, Defender Operational, PowerShell Operational and Sysmon Operational where installed. Custom can add discovered channels."),
        ("host, volumes, settings", "OS edition and build, boot time, time zone, local fixed volumes, capacity and selected Windows version metadata."),
        ("services, tasks, startup, applications", "Service state and startup mode, scheduled task name and state, startup entry location and machine application registration."),
        ("users, groups, sessions", "Local account name, enabled status, SID and last logon where available, local group name and SID, and logon-session metadata."),
        ("files", "Up to 32 explicitly selected local regular files. Captures metadata and optional SHA-256 for files up to 64 MiB. Detects changes during hashing."),
    ), (2.62, 4.18))
    body(doc, "The default event window is 24 hours. Extended and Custom allow up to 168 hours. Each source has a record, output and time limit. Preview scope for the exact choices, upper storage estimate and sensitive fields. Collection reads source evidence and writes only to the selected destination.", space_before=9)

    page(doc, "Extended forensic sources")
    body(doc, "Extended adds operational evidence that can help explain execution, remote access and security configuration. The underlying Windows logging configuration determines what is available. Use Discover channels to choose additional installed channels in Custom. The application uses current settings and preserves those settings during collection.")
    table(doc, ("Extended collector", "What it helps you review"), (
        ("events-tasks and events-wmi", "Scheduled task and Windows Management Instrumentation activity."),
        ("events-rdp and events-winrm", "Remote Desktop session events and Windows Remote Management events."),
        ("events-code-integrity and events-applocker", "Recorded checks on executable trust and executable rule enforcement."),
        ("events-firewall and events-dns-client", "Firewall operational events and DNS client activity where enabled."),
        ("neighbors and dns-cache", "Local link neighbors and recently cached name resolutions. Treat the records as snapshots."),
        ("hotfixes and firewall-profiles", "Available Windows hotfix metadata and firewall profile settings such as logging status."),
    ), (2.55, 4.25))
    headings(doc, "What a live capture can answer", "A live capture can show available local log records, connections and system metadata. It can help you identify when a service, task or account changed. Compare the result with change records and evidence from the network, identity provider or endpoint security service.")
    headings(doc, "When to use a forensic specialist", "A complete forensic acquisition may require memory, a disk image, registry hive analysis, deleted-file recovery, endpoint telemetry or cloud audit logs. Windows Traige is a bounded triage tool. Its catalog excludes credential stores and raw disk or memory acquisition. A qualified responder can select additional approved acquisition methods when needed.")

    page(doc, "Collection results and administrator retry")
    headings(doc, "Review coverage", "Every planned source has a result. Collected means the query completed within the selected scope. An empty event window is recorded explicitly. Partial identifies a limit or incomplete payload. Access Denied, Unavailable and Failed identify distinct gaps. Cancel stops finalization and leaves existing completed archives available.")
    headings(doc, "Retry denied event sources", "After a native collection records an eligible denial, choose Retry with Administrator Access. Windows may ask for approval on the secure desktop. The helper retries denied built-in event sources using the original time window. The resulting ZIP references the prior archive and retains its successful payloads. Normalized events may be returned while raw EVTX remains unavailable on this retry path.")
    headings(doc, "Read the result after declining", "If you decline UAC or Windows denies the elevated query, the updated coverage explains the result and preserves the original bundle. CLI runs are unattended by default. Use --elevate only when a Windows prompt is expected.")
    headings(doc, "Handle evidence privately", "Process arguments, event XML, file paths and identifiers may contain sensitive information. Keep collection and cases in a private, access-controlled local directory. Handle the evidence ZIP and detached digest through separate trusted paths when authenticity matters. Preserve original evidence and share derived material only as authorized.")
    headings(doc, "Verify an evidence ZIP", "Choose Verify ZIP in the case view. Internal verification checks declared archive members and their digests. A detached SHA-256 can confirm a byte-for-byte match against a value obtained independently. Source accuracy remains unverified. A verification or import error leaves prior case records and archives available.")

    page(doc, "Start with the evidence summary")
    headings(doc, "Open the summary", "After importing a ZIP or saved EVTX, choose Evidence Summary in the sidebar. The first section shows the number of records, bundles and source computers, the observed time range, missing timestamps, detached ZIP checksums that matched and the number of original archived logs retained. Refresh summary after adding evidence to an open case.")
    headings(doc, "Review the activity", "The workbench groups matching event channels and IDs into review leads. For example, a System 7045 event points to a service installation. It may be normal administration or activity that requires follow-up. Pick a lead and select Open highlighted record to see the latest matching event and its exact evidence reference.")
    headings(doc, "Check gaps before deciding", "Read the status, reason and next action for each affected run. For a denied built-in log, use an authorized retry or ask the source owner for an export. For a record limit, narrow the collection window or request a saved log. An empty window can reflect the selected dates or retention. A missing or disabled channel may require an earlier export or records from an independent source.")
    headings(doc, "Take the next defensive step", "Preserve the original ZIP and separately held digest. Compare unusual events with maintenance records and independent sources. If compromise is suspected, contact the incident-response lead through a trusted channel and follow the approved containment process. Avoid changing the original host before coordinating preservation.")
    headings(doc, "Save an overview for handoff", "Enter a local .txt path or choose Browse, then select Save summary. The summary contains coverage, leads with references, and next steps. Use Findings and Reports for detailed records and operator annotations. Use Raw JSON when another tool needs the structured summary.")

    page(doc, "Import a saved Windows event log")
    headings(doc, "Choose the original EVTX", "In Event Viewer, select the authorized log or filtered view and save its events as an .evtx file. You can also ask a system owner or an investigation tool for an export in that format. Preserve the supplied file, the export time and the person who provided it. Ask for the SHA-256 over a separate trusted channel when it is available.")
    headings(doc, "Add the log to your case", "Open Cases and Timeline and select Import evidence. Browse to the .evtx or paste its path. Enter the case folder and, if supplied, choose the detached SHA-256 file for that EVTX. Select Verify and import. An import opens the case timeline when it finishes. Use Verify ZIP only to check a Windows Traige ZIP separately.")
    headings(doc, "Review what was preserved", "Coverage shows the original filename, SHA-256, detached source-checksum result and observed event times in UTC. The case keeps a byte-for-byte EVTX copy in its evidence ZIP. The timeline shows source computer, channel, event ID and references. Select Native event to open the Windows-rendered XML for the selected archived event.")
    headings(doc, "Handle duplicates and failures", "Importing the same EVTX bytes twice retains the existing records even if the file was renamed. A checksum mismatch or unreadable file is rejected. Request another copy from the source owner. The app supports EVTX and indexed output up to 128 MiB each and up to 100,000 events per import. Ask for smaller time-based exports when a log exceeds those limits.")
    headings(doc, "Keep the source context", "The event range describes what the saved file contains. Compare it with the incident time and the source's retention. Preserve the original export and any separately held checksum even after importing. Ask the response lead about disk images, memory or independent sensor evidence when the incident requires a wider investigation.")

    page(doc, "Investigation and reporting")
    headings(doc, "Create or reopen a case", "Use Import evidence to enter or browse for a Windows Traige ZIP or saved EVTX, enter a case folder path, and optionally enter a trusted detached checksum. Choose Verify and import. Use Open case for a folder containing case.sqlite3. A case can contain several evidence sources. A duplicate import retains existing notes. Coverage shows the source details and gaps.")
    headings(doc, "Search and read provenance", "Use the evidence type selector, search field, Event ID and More filters. More filters supports channel, severity, PID, executable path, IP, port, archive SHA-256 and a time range. Display local time changes the timeline display. The record detail preserves UTC source and acquisition times. Use Native event to read a referenced EVTX record locally where available.")
    headings(doc, "Interpret related records", "Process links compare the same archive, process ID, creation time and a short time window around the snapshot. The details distinguish a time-based match, ambiguous candidates and unavailable context. Windows publisher process IDs describe the process that emitted the event. Use the raw record and source fields to evaluate the relationship.")
    headings(doc, "Preserve analysis and export", "Save a filter to reuse it. Select a row to attach a note, bookmark, finding or hypothesis. Use Findings and Reports to enter an operator identity, refresh annotations, review a finding and choose an export destination. HTML includes scope, verification, gaps, records and source references. JSON includes structured records and annotations. CSV exports record rows. Select the single-record option when you need a focused export.")
    headings(doc, "Keyboard operation", "Use Tab and Shift+Tab to move between controls. Use arrow keys to navigate lists and the timeline. Ctrl+I opens the evidence import dialog. Enter applies the timeline search or Event ID. The status bar shows progress and the Cancel operation button while work is running.")

    page(doc, "Practice reading a timeline")
    headings(doc, "Find a known record", "Import the generated fixture. On Cases and Timeline, enter 7045 in the Event ID field and select Filter. Select the resulting System event. Pretty view explains the event and lists the observed time, collection time, source computer, event record number and archive digest.")
    headings(doc, "Check the related process", "The fixture contains two processes using the same process ID at different times. Review the related process section. Only the process with a compatible creation time and observation window should link to the event. Select Raw JSON to compare the precise timestamps and process fields.")
    headings(doc, "Record the reason for your conclusion", "Select Add annotation. Choose Note for supporting context, Bookmark for a reference to revisit, Finding for a verified conclusion, or Hypothesis for an interpretation to test. Include the evidence you corroborated and any relevant gap. Use Findings and Reports to mark a finding reviewed with an operator identity.")
    headings(doc, "Export the result", "Choose Findings and Reports. Enter an output path ending in .html, .csv or .json, or select Choose report path. The current filter and page determine the records unless you check Export only the selected record. Select Export report. Review the exported file before sharing it.")
    headings(doc, "Keep the case and the evidence", "The case folder contains a local index, copied verified evidence and your annotations. Keep it in a private folder. The source evidence ZIP retains its own detached checksum. Preserve both when handing off an investigation.")

    page(doc, "Command line workflow")
    body(doc, "Run these PowerShell examples from the extracted folder. Replace example paths with authorized local paths. Create the Capture directory first. Use the actual archive name generated by the application and a separately held checksum where available.")
    code(doc, [
        r".\WindowsTraige.Cli.exe --help",
        r".\WindowsTraige.Cli.exe --version",
        r".\WindowsTraige.Cli.exe collect --profile standard --out .\Capture --plan",
        r".\WindowsTraige.Cli.exe collect --profile standard --out .\Capture",
        r".\WindowsTraige.Cli.exe verify .\evidence.zip --checksum .\evidence.sha256",
        r".\WindowsTraige.Cli.exe import .\evidence.zip --case .\Case --checksum .\evidence.sha256",
        r".\WindowsTraige.Cli.exe import .\saved.evtx --case .\Case --checksum .\saved.sha256",
        r".\WindowsTraige.Cli.exe collect --profile quick --out .\Capture --evidence disk-image=.\saved.img",
        r".\WindowsTraige.Cli.exe query .\Case --event-id 7045 --json",
        r".\WindowsTraige.Cli.exe summary .\Case",
        r".\WindowsTraige.Cli.exe report .\Case --out .\case-report.html",
        r".\WindowsTraige.Cli.exe retry .\evidence.zip --out .\Capture --elevate",
    ])
    headings(doc, "Scripting", "JSON results go to standard output and progress or errors go to standard error. Query defaults to a text summary unless --json is supplied. Use --help after a command for its supported arguments. Choose --start and --end with explicit UTC offsets for a bounded timeline search.")
    table(doc, ("Exit", "Result"), (
        ("0", "Successful operation"), ("2", "Partial collection or one or more unavailable sources"),
        ("3", "Invalid request, unsupported schema or integrity mismatch"), ("4", "Access denied"),
        ("5", "Cancelled"), ("6", "Failed local or Windows operation"),
    ), (1.0, 5.8))

    page(doc, "Assistant setup and disclosure")
    body(doc, "Evidence collection, verification, search and reporting work offline. AI starts off. Google Gemini, OpenAI and Anthropic Claude are available in the provider selector. See the verification record for the live-tested provider. API access, model availability and billing depend on your provider account.")
    headings(doc, "Understand models and API keys", "A model is the provider's service that generates replies. Choose one of the named options. For Gemini, try Gemini 3.5 Flash-Lite first. An API key lets the application use your provider account. Keep the key private. The key is entered in a masked field or loaded from a local text file.")
    headings(doc, "Connect and check the account", "Select the provider and model. Enter your key or choose Load key from file. Turn on Enable network AI for this session. Check key and list models confirms access to the provider's model list. A listed model may still have usage limits. Choose Enter model ID manually for an exact ID from the provider.")
    headings(doc, "Send a first message", "Try asking how to open an evidence ZIP. Select Review and send or press Ctrl+Enter. Read the preview and approve the request if the displayed information is appropriate. The chat keeps recent messages in this session for follow-up questions. Use New chat to start over.")
    headings(doc, "Disconnect and manage credentials", "Disconnect clears the active key and conversation. Keys are session-only by default. Save, load and forget a key through Windows Credential Manager if you choose. For the CLI, set OPENAI_API_KEY, ANTHROPIC_API_KEY or GEMINI_API_KEY in the invoking process environment. Review ai --preview and pass its hash with --approve-excerpts.")

    page(doc, "Let the assistant help with a case")
    headings(doc, "Attach evidence you can share", "Select a timeline record and choose Use in Assistant. Repeat for relevant records, up to eight. Include case overview adds counts, collection statuses and review leads from the current case. Review and send shows the provider, model, message, included chat context, excerpts and case overview. Raw evidence ZIPs and original event text stay local.")
    headings(doc, "Ask for an evidence based answer", "Ask a specific question such as What does this event show and what should I check next. The assistant can use the approved excerpts and cite the archive digest and record ID. Open the cited record in the timeline and compare it with independent evidence. Treat an unresolved citation or generated finding as a lead to review.")
    headings(doc, "Review a proposed action", "Allow case tools enables approved excerpt retrieval, search and proposals in compatible models. The assistant can propose local search, navigation, opening a summary, collection, import, verification, reports, bookmarks and annotations. Open Review proposed action, read the exact operation and choose whether to apply it. Paths, broader scope and elevation remain under your control.")
    headings(doc, "Troubleshoot a reply", "For a rejected key, check that it is an API key for the selected provider. Try another named model if your account lacks the selected model or the provider is unavailable. Disable Allow case tools for a text-only model. If the request included evidence, review the scope again before resending.")
    headings(doc, "Keep disclosures intentional", "Each send reviews the data that leaves the computer, including selected recent chat messages. Clear attached records when changing tasks. Use New chat to clear conversation context. Disconnect when finished. Live requests are subject to the provider's data handling and billing terms.")

    page(doc, "Collection controls at a glance")
    table(doc, ("Control", "What it does"), (
        ("Profile", "Chooses the default sources. Quick covers recent system activity, Standard adds broader Windows evidence, Extended adds operational sources, and Custom lets you choose exact sources."),
        ("Event window in hours", "How far back to look in Windows event logs. Use the incident time to choose this value."),
        ("Maximum records per source", "Caps each local collector. If coverage shows a record limit, use a narrower time window."),
        ("Custom collector IDs and event channels", "In Custom, enter comma-separated names. The collector tables give the IDs. Discover channels lists installed Windows event channels and fills the selected names."),
        ("Include process command lines", "Adds the commands used to start processes in Extended or Custom. Commands can contain private values."),
        ("Select files, Hash selected files, Clear files", "Choose files for metadata collection, optionally compute their SHA-256, or clear the selection. Use Set up for supplemental originals you want inside the ZIP."),
        ("Optional evidence and Set up", "Each checked option adds an external file source. Set up opens its file picker and optional details. Uncheck a source to leave it out of this collection."),
        ("Collection output directory and Browse", "Choose the private local folder where the ZIP and checksum will be saved."),
        ("Preview scope and Start collection", "Preview lists the sources and selected originals. Start asks you to confirm the scope and then creates the bundle."),
        ("Retry with Administrator Access", "Retries eligible denied Windows event sources from the last capture after Windows asks for approval."),
        ("Open captured evidence in a case", "Fills the evidence ZIP and checksum in the case form. Enter the case folder to finish importing."),
    ), (2.10, 4.70))

    page(doc, "Case and timeline controls at a glance")
    table(doc, ("Control", "What it does"), (
        ("Import evidence and Browse for evidence", "Opens the import form and picks a Windows Traige ZIP or saved EVTX. Ctrl+I also opens the form."),
        ("Evidence file, Case folder, Detached SHA-256 file", "Enter the file, the case’s working folder and any separately supplied checksum. Verify and import checks and indexes the evidence."),
        ("Open case and Open existing case", "Browse to a case folder or open the case folder entered in the form."),
        ("Verify ZIP, Verify ZIP only, Close import", "Verify ZIP opens the form. Verify ZIP only checks the archive without adding it to a case. Close import hides the form."),
        ("Coverage", "Shows collection results, gaps and original file hashes for the open case."),
        ("Search evidence, Event ID, All evidence, Filter", "Search record text, enter a Windows event number such as 7045, or choose a record type. Filter applies the selection."),
        ("More filters", "Narrow by channel, severity, process ID, executable path, IP address, port, start or end time with timezone, or archive fingerprint. Blank filters leave those fields unrestricted."),
        ("Display local time, Save filter, Load filter", "Switch the displayed timezone, name and save the current search, or reopen a saved search."),
        ("Previous page and Next page", "Move through the timeline results. Select a row to show its evidence details."),
        ("Native event and Save original", "Open the referenced Windows event XML or create a verified working copy of a supplemental original."),
        ("Add annotation and Use in Assistant", "Add a note, bookmark, finding or hypothesis to the selected record, or attach an approved excerpt for review in Assistant."),
    ), (2.10, 4.70))

    page(doc, "Summary and reporting controls at a glance")
    table(doc, ("Control", "What it does"), (
        ("Refresh summary", "Rebuild the summary from the open case after importing evidence or changing cases."),
        ("Review lead and Open highlighted record", "Pick a flagged item and open the matching timeline record. A lead is a starting point for review."),
        ("Summary output path, Browse, Save summary", "Enter or choose a new local .txt path, then save a readable copy of the current summary."),
        ("Operator identity", "Enter the name to record on annotations and reviews, when appropriate."),
        ("Refresh annotations", "Reload the case notes, bookmarks, findings and hypotheses."),
        ("Mark finding reviewed", "Enter the annotation ID shown in Findings and Reports. Windows Traige records the reviewer name from Operator identity."),
        ("Report output path and Choose report path", "Enter or choose a new local .html, .json or .csv filename."),
        ("Export only the selected record and Export report", "Check the box to export one selected timeline record. With the box clear, export the results from the current timeline filters and page."),
    ), (2.20, 4.60))
    headings(doc, "Controls shared by the workbench", "View changes between Pretty view and Raw JSON. Appearance changes the color theme. Cancel operation stops supported work in progress. The status bar reports the result or explains what the app needs. The GitHub and LinkedIn icons open the author’s profiles.")

    page(doc, "Assistant controls at a glance")
    table(doc, ("Control", "What it does"), (
        ("Enable network AI for this session", "Allows requests to the provider during this session. Review the outgoing content before sending."),
        ("Show or Hide connection setup and Disconnect", "Show or hide the provider controls, or end the active connection and clear its key and conversation."),
        ("AI provider, AI model and Manual model ID", "Select the provider and a named model. Choose Enter model ID manually to type the exact ID from the provider."),
        ("Session API credential and Check key and list models", "Paste the provider API key into the masked field. Check key and list models tests access and lists available models."),
        ("Load key from file and Load saved key", "Read a key from a local file or from Windows Credential Manager."),
        ("Save key and Forget saved key", "Save or remove the provider key in Windows Credential Manager."),
        ("Allow case tools and Include case overview", "Allow supported models to use approved case excerpts and propose local actions. Include case overview adds counts, gaps and review leads to the request preview."),
        ("OpenAI legacy text interface", "Selects the OpenAI text interface for compatible models when using OpenAI."),
        ("Clear attached records and New chat", "Remove the selected excerpts and case overview from the request, or start a fresh conversation."),
        ("Message, Review and send, Review proposed action", "Type the question, check the outgoing preview and approve it if appropriate. Review a proposed local action separately before applying it."),
    ), (2.15, 4.65))

    page(doc, "Troubleshooting and rebuilding")
    table(doc, ("Symptom", "Check"), (
        ("Executable cannot start", "Extract the full portable ZIP. Confirm the two runtime directories are beside the binaries and use Windows x64."),
        ("Destination unavailable", "Choose an existing private output folder on a local NTFS volume with sufficient free space. The application rejects reparse points and existing final filenames."),
        ("Security or another source denied", "Review the source coverage. Retry a denied built-in event source only with authorized UAC consent."),
        ("No events visible", "Check the channel, time window, event limit and filter. Empty windows and unavailable sources appear in coverage."),
        ("Evidence or checksum rejected", "Verify the file against the original separately obtained SHA-256. Request a fresh copy if the bytes changed or a smaller EVTX export if you reached an import limit."),
        ("Provider cannot respond", "Check the selected model, provider credential and entitlement. Use text mode if tools are unsupported."),
    ), (2.15, 4.65))
    headings(doc, "Rebuild the package", "Use Windows x64, PowerShell 7 and CPython 3.12.14 AMD64. From the v2.0 source folder, follow docs/build.md to download the verified wheels, then run scripts/Build.ps1 with -Fresh and a new build ID. The output includes executable hashes, Authenticode status and a ZIP checksum.")
    headings(doc, "Review current limits", "Windows Traige uses bounded read-only collection. The elevated retry can save normalized events without an original EVTX. Import an authorized saved log when you need the native file. A full investigation can also require specialist acquisition or independent evidence. Check the local verification record for the tested Windows build and Gemini workflow.")
    doc.save(destination)


if __name__ == "__main__":
    make(Path(argv[1]))
