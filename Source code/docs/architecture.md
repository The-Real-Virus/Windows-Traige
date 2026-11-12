# Windows Traige architecture

The package is a Python and Qt Widgets application with two native Windows entry points. Both call the same collection, evidence, case, reporting, and assistant modules. The investigation workspace is local SQLite with schema migration and transactional imports. Case operations use opaque archive and record identities. Archive content is untrusted and is rendered as plain text.

The collection plan binds a bounded local catalog to a time window. Native adapters only invoke fixed Windows queries. Original evidence and derived case annotations have separate storage. The distribution uses PyInstaller onedir bundles to avoid executable extraction to the host temporary directory at launch.

The pinned Qt runtime targets Windows 10 x64 version 1809 or later and Windows 11 x64. Acceptance is recorded against the specific host tested. Source licensing is pending owner selection. See https://doc.qt.io/qt-6.10/windows.html.
