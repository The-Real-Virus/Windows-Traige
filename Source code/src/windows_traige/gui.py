"""Native Qt Widgets workbench for Windows Traige."""

import argparse
import json
import os
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from threading import Event

from PySide6.QtCore import QObject, QSettings, QSize, Qt, QThread, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QIcon, QKeySequence, QPalette
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog,
    QFormLayout, QFrame, QGridLayout, QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit,
    QListWidget, QMainWindow, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QToolButton,
    QScrollArea, QSpinBox, QSplitter, QStackedWidget, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from . import VERSION, assistant, branding, bundle, case, collect, credentials, native, present, report, supplemental, summary
from .common import Cancelled, Invalid

COLLECTION_PAGE, CASE_PAGE, SUMMARY_PAGE, REPORTS_PAGE, ASSISTANT_PAGE = range(5)


def layout(widget, kind=QVBoxLayout):
    result = kind(widget)
    result.setContentsMargins(0, 0, 0, 0)
    result.setSpacing(9)
    return result


def pretty(value):
    return json.dumps(value, indent=2, ensure_ascii=False)


def readable(text, name, wraps=True):
    label = QLabel(text)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(wraps)
    label.setObjectName(name)
    return label


def editor(name, read_only=False):
    widget = QPlainTextEdit()
    widget.setAccessibleName(name)
    widget.setReadOnly(read_only)
    widget.setTabChangesFocus(True)
    return widget


class Job(QObject):
    succeeded = Signal(object)
    failed = Signal(str)
    changed = Signal(str, int)
    finished = Signal()

    def __init__(self, operation, cancel):
        super().__init__()
        self.operation, self.cancel = operation, cancel

    def run(self):
        try:
            self.succeeded.emit(self.operation(self.cancel, self.changed.emit))
        except (Cancelled, Invalid, native.NativeError) as exc:
            self.failed.emit(str(exc))
        except PermissionError:
            self.failed.emit("Windows denied access. Check that you can read the evidence and write to the destination.")
        except FileExistsError:
            self.failed.emit("A file already exists at that location. Choose a new filename.")
        except Exception as exc:
            self.failed.emit(f"Operation failed ({type(exc).__name__}). Check the selected path and case state.")
        finally:
            self.finished.emit()


class Window(QMainWindow):
    def __init__(self, initial_case=None, initial_bundle=None):
        super().__init__()
        self.setWindowTitle("Windows Traige")
        self.setWindowIcon(QIcon(str(branding.ICON)))
        self.setMinimumSize(720, 470)
        screen = QApplication.primaryScreen().availableGeometry()
        self.resize(min(1120, screen.width() - 34), min(740, screen.height() - 58))
        self.case_path = initial_case
        self.rows, self.offset, self.extra = [], 0, {}
        self.last_bundle = None
        self.collection_folder = None
        self.thread = self.job = self.cancel_event = self.session = None
        self.after_job = None
        self.chosen_files = []
        self.disclosed = []
        self.proposals = []
        self.views = {}
        self.case_summary = None
        self.chat_history = []
        self.last_answer = None
        self.pending_chat = None
        settings_file = os.environ.get("WINDOWSTRAIGE_SETTINGS")
        self.settings = (QSettings(settings_file, QSettings.Format.IniFormat) if settings_file else
                         QSettings(QSettings.Format.IniFormat, QSettings.Scope.UserScope, "ViRuS", "Windows Traige"))

        root = QWidget()
        outer = layout(root, QHBoxLayout)
        outer.setSpacing(0)
        rail = QFrame()
        rail.setObjectName("rail")
        rail.setFixedWidth(172)
        rail_layout = layout(rail)
        rail_layout.setContentsMargins(15, 19, 13, 16)
        rail_layout.addWidget(readable("WINDOWS\nTRAIGE", "wordmark"))
        self.nav = QListWidget()
        self.nav.setAccessibleName("Workbench navigation")
        self.nav.addItems(["Collection", "Cases and Timeline", "Evidence Summary", "Findings and Reports", "Assistant"])
        self.nav.setUniformItemSizes(True)
        rail_layout.addWidget(self.nav, 1)
        rail_layout.addWidget(readable(VERSION, "caption"))
        rail_layout.addWidget(readable("Made By ViRuS", "credit"))
        rail_layout.addWidget(readable("All rights reserved © 2026", "caption"))
        self.profile_buttons = {}
        links = QHBoxLayout()
        for name, url in branding.PROFILES.items():
            button = QToolButton()
            button.setAccessibleName(f"Open {name} profile")
            button.setToolTip(f"Open ViRuS on {name}")
            button.setIconSize(QSize(19, 19))
            button.clicked.connect(lambda _checked=False, address=url: self.open_profile(address))
            self.profile_buttons[name] = button
            links.addWidget(button)
        links.addStretch()
        rail_layout.addLayout(links)
        outer.addWidget(rail)

        shell = QWidget()
        body = layout(shell)
        body.setContentsMargins(21, 16, 21, 12)
        preferences = QHBoxLayout()
        preferences.addStretch()
        self.view_mode = QComboBox()
        self.view_mode.setAccessibleName("Evidence display format")
        self.view_mode.addItems(["Pretty view", "Raw JSON"])
        self.view_mode.currentIndexChanged.connect(self.refresh_views)
        self.theme = QComboBox()
        self.theme.setAccessibleName("Appearance")
        self.theme.addItems(["System", "Light", "Dark"])
        self.theme.setCurrentText(self.settings.value("appearance", "System"))
        self.theme.currentTextChanged.connect(self.change_theme)
        preferences.addWidget(readable("View", "caption", False))
        preferences.addWidget(self.view_mode)
        preferences.addSpacing(12)
        preferences.addWidget(readable("Appearance", "caption", False))
        preferences.addWidget(self.theme)
        body.addLayout(preferences)
        self.pages = QStackedWidget()
        for title, subtitle, page in (
            ("Collection", "Plan a bounded capture and review its coverage.", self.collection_page),
            ("Cases and Timeline", "Verify evidence, filter records and inspect source references.", self.case_page),
            ("Evidence Summary", "Review what was collected, what needs attention, and what to do next.", self.summary_page),
            ("Findings and Reports", "Review annotations and export records with their provenance.", self.report_page),
            ("Assistant", "Review disclosure before sending selected excerpts to a provider.", self.ai_page),
        ):
            view = QWidget()
            content = layout(view)
            content.addWidget(readable(title, "heading"))
            content.addWidget(readable(subtitle, "caption"))
            if title == "Collection":
                scroll = QScrollArea()
                scroll.setWidgetResizable(True)
                scroll.setFrameShape(QFrame.Shape.NoFrame)
                controls = QWidget()
                page(layout(controls))
                scroll.setWidget(controls)
                content.addWidget(scroll, 1)
            else:
                page(content)
            self.pages.addWidget(view)
        body.addWidget(self.pages, 1)
        status_row = QHBoxLayout()
        self.state = readable("Ready. AI is off.", "status")
        self.spinner = QProgressBar()
        self.spinner.setRange(0, 0)
        self.spinner.setAccessibleName("Operation in progress")
        self.spinner.setMaximumWidth(120)
        self.spinner.hide()
        self.stop = self.button("Cancel operation", self.cancel_current)
        self.stop.setEnabled(False)
        status_row.addWidget(self.state, 1)
        status_row.addWidget(self.spinner)
        status_row.addWidget(self.stop)
        body.addLayout(status_row)
        outer.addWidget(shell, 1)
        self.setCentralWidget(root)
        self.nav.currentRowChanged.connect(self.navigate)
        self.nav.setCurrentRow(CASE_PAGE if initial_case or initial_bundle else COLLECTION_PAGE)
        QApplication.styleHints().colorSchemeChanged.connect(self.apply_style)
        self.apply_style()
        if initial_case:
            self.refresh_case()
        if initial_bundle:
            from PySide6.QtCore import QTimer
            QTimer.singleShot(0, lambda: self.show_import_form(initial_bundle))

    def open_profile(self, url):
        if not QDesktopServices.openUrl(QUrl(url)):
            self.status("Windows could not open the profile in the default browser.")

    def change_theme(self, mode):
        self.settings.setValue("appearance", mode)
        self.apply_style()

    def apply_style(self, *_):
        mode = self.theme.currentText()
        dark = mode == "Dark" or (mode == "System" and
                                 QApplication.styleHints().colorScheme() == Qt.ColorScheme.Dark)
        bg, panel, text, muted, line, accent, selection = (
            ("#111b28", "#192737", "#eff5fc", "#afbed1", "#3c4c63", "#75b7ff", "#273e5c") if dark else
            ("#f3f6fa", "#ffffff", "#14243a", "#415872", "#c3cddd", "#135faf", "#dbeaff")
        )
        palette = QPalette()
        for role, color in {
            "Window": bg, "WindowText": text, "Base": panel, "AlternateBase": bg, "Text": text,
            "Button": panel, "ButtonText": text, "PlaceholderText": muted, "Highlight": selection,
            "HighlightedText": text, "ToolTipBase": panel, "ToolTipText": text, "Link": accent,
        }.items():
            palette.setColor(getattr(QPalette.ColorRole, role), QColor(color))
        for role in (QPalette.ColorRole.ButtonText, QPalette.ColorRole.Text, QPalette.ColorRole.WindowText):
            palette.setColor(QPalette.ColorGroup.Disabled, role, QColor(muted))
        QApplication.setPalette(palette)
        for name, button in self.profile_buttons.items():
            button.setIcon(branding.profile_icon(name, accent))
        self.setStyleSheet(f"""
            QMainWindow, QWidget#rail {{ background:{bg}; color:{text}; }}
            QFrame#rail {{ border-right:1px solid {line}; }}
            QLabel {{ color:{text}; }}
            QLabel#heading {{ font-size:25px; font-weight:700; }}
            QLabel#wordmark {{ font-size:19px; font-weight:750; color:{accent}; padding:3px 0 14px; }}
            QLabel#caption, QLabel#status {{ color:{muted}; }}
            QLabel#credit {{ color:{text}; font-weight:600; }}
            QListWidget, QPlainTextEdit, QTableWidget {{ background:{panel}; color:{text};
                border:1px solid {line}; border-radius:5px; selection-background-color:{selection};
                selection-color:{text}; }}
            QListWidget::item {{ min-height:34px; padding:3px; }}
            QHeaderView::section {{ background:{bg}; color:{text}; padding:5px; border:0; }}
            QPushButton {{ min-height:25px; padding:2px 8px; }}
            QLineEdit, QComboBox, QSpinBox {{ min-height:25px; background:{panel}; color:{text}; }}
            QToolButton {{ border:1px solid {line}; border-radius:5px; padding:5px; background:{panel}; }}
            QToolButton:hover, QToolButton:focus {{ border-color:{accent}; }}
            QPushButton:focus, QLineEdit:focus, QListWidget:focus, QTableWidget:focus,
            QPlainTextEdit:focus, QComboBox:focus {{ border:2px solid {accent}; }}
        """)

    def button(self, label, callback, shortcut=None):
        item = QPushButton(label)
        item.clicked.connect(callback)
        if shortcut:
            item.setShortcut(QKeySequence(shortcut))
        return item

    def row(self, target, *widgets):
        row = QHBoxLayout()
        row.setSpacing(7)
        for widget in widgets:
            row.addWidget(widget)
        target.addLayout(row)
        return row

    def navigate(self, index):
        self.pages.setCurrentIndex(index)
        if index == SUMMARY_PAGE:
            self.refresh_summary()
        elif index == REPORTS_PAGE and self.case_path:
            self.refresh_findings()

    def present_view(self, widget, kind, data):
        self.views[widget] = (kind, data)
        raw = self.view_mode.currentIndex() == 1
        value = summary.text(data) if kind == "summary" and not raw else present.format_view(kind, data, raw)
        widget.setPlainText(value)

    def clear_view(self, widget, message):
        self.views.pop(widget, None)
        widget.setPlainText(message)

    def refresh_views(self, *_):
        for widget, (kind, data) in list(self.views.items()):
            self.present_view(widget, kind, data)
        if self.last_answer is not None:
            self.refresh_chat()

    def status(self, message):
        self.state.setText(message)

    def guarded(self, action):
        try:
            return action()
        except (OSError, Invalid, ValueError) as exc:
            self.status(str(exc) if isinstance(exc, Invalid) else f"Operation failed ({type(exc).__name__})")
        except Exception as exc:
            self.status(f"Operation failed ({type(exc).__name__})")

    def start(self, operation, done):
        if self.thread:
            self.status("An operation is already running.")
            return
        self.after_job = None
        self.cancel_event = Event()
        self.thread = QThread(self)
        self.job = Job(operation, self.cancel_event)
        self.job.moveToThread(self.thread)
        self.thread.started.connect(self.job.run)
        self.job.changed.connect(self.job_progress)
        self.job.succeeded.connect(self.accept_job)
        self.job.failed.connect(self.job_failed)
        self.job.finished.connect(self.thread.quit)
        self.job.finished.connect(self.job.deleteLater)
        self.thread.finished.connect(self.release_job)
        self.thread.finished.connect(self.thread.deleteLater)
        self.after_job = done
        self.spinner.show()
        self.stop.setEnabled(True)
        self.status("Working…")
        self.thread.start()

    def job_progress(self, phase, count):
        self.status(f"{phase}  [{count}]")

    def accept_job(self, result):
        if self.after_job:
            self.guarded(lambda: self.after_job(result))

    def job_failed(self, message):
        self.status(message)
        if self.pending_chat is not None:
            self.ai_output.appendPlainText(f"\nRequest status\n{message}")
            self.pending_chat = None

    def release_job(self):
        self.thread = self.job = self.cancel_event = self.after_job = None
        self.spinner.hide()
        self.stop.setEnabled(False)

    def cancel_current(self):
        if self.cancel_event:
            self.cancel_event.set()
            self.status("Cancellation requested…")

    def closeEvent(self, event):
        if self.thread:
            self.cancel_current()
            event.ignore()
        else:
            event.accept()

    def collection_page(self, body):
        self.profile = QComboBox()
        self.profile.setAccessibleName("Collection profile")
        self.profile.addItems(["Quick", "Standard", "Extended", "Custom"])
        self.profile.setCurrentText("Standard")
        self.profile_help = readable("", "caption")
        self.hours = QSpinBox()
        self.hours.setRange(1, 168)
        self.hours.setValue(24)
        self.hours.setAccessibleName("Event window hours")
        self.rows_limit = QSpinBox()
        self.rows_limit.setRange(1, collect.MAX_ROWS)
        self.rows_limit.setValue(collect.MAX_ROWS)
        self.rows_limit.setAccessibleName("Maximum records per collector")
        form = QFormLayout()
        form.addRow("&Profile", self.profile)
        form.addRow("Event window in &hours", self.hours)
        form.addRow("Maximum &records per source", self.rows_limit)
        body.addLayout(form)
        body.addWidget(self.profile_help)
        self.custom_collectors = QLineEdit()
        self.custom_collectors.setAccessibleName("Custom collector IDs")
        self.custom_collectors.setPlaceholderText("Custom collector IDs separated by commas")
        self.custom_channels = QLineEdit()
        self.custom_channels.setAccessibleName("Custom event channels")
        self.custom_channels.setPlaceholderText("Custom event channels separated by commas")
        body.addWidget(self.custom_collectors)
        self.row(body, self.custom_channels, self.button("Discover channels", self.discover_channels))
        self.process_args = QCheckBox("Include process command lines")
        self.hash_files = QCheckBox("Hash selected files")
        self.select_files = self.button("Select files…", self.pick_files)
        self.clear_files = self.button("Clear files", self.reset_files)
        self.row(body, self.process_args, self.hash_files, self.select_files, self.clear_files)
        self.supplemental_controls(body)
        self.output = QLineEdit()
        self.output.setAccessibleName("Collection output directory")
        self.output.setPlaceholderText("Choose a private local output directory")
        self.row(body, self.output, self.button("Browse…", self.pick_output))
        self.row(body, self.button("Preview scope", self.show_plan), self.button("Start collection", self.start_collection),
                 self.button("Retry with Administrator Access", self.retry_collection))
        self.open_capture = self.button("Open captured evidence in a case", self.open_last_capture)
        self.open_capture.setEnabled(False)
        body.addWidget(self.open_capture)
        self.capture_detail = editor("Collection scope and coverage", True)
        self.capture_detail.setMinimumHeight(108)
        self.capture_detail.setPlainText("Choose a profile and destination, then preview the source list and sensitive fields.")
        body.addWidget(self.capture_detail, 1)
        self.profile.currentTextChanged.connect(self.update_profile)
        self.update_profile(self.profile.currentText())

    def supplemental_controls(self, body):
        body.addWidget(readable("Optional evidence for this ZIP", "caption"))
        self.evidence_choices = {}
        self.evidence_files = {}
        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        for index, (kind, label) in enumerate(supplemental.LABELS.items()):
            check = QCheckBox(label)
            button = self.button("Set up…", lambda _=False, key=kind: self.configure_evidence(key))
            button.setAccessibleName(f"Set up {label.lower()}")
            button.setEnabled(False)
            check.toggled.connect(button.setEnabled)
            entry = QWidget()
            row = QHBoxLayout(entry)
            row.setContentsMargins(0, 0, 0, 0)
            row.addWidget(check, 1)
            row.addWidget(button)
            grid.addWidget(entry, index // 2, index % 2)
            self.evidence_choices[kind] = check
        body.addLayout(grid)

    def configure_evidence(self, kind):
        title = supplemental.LABELS[kind]
        saved = self.evidence_files.get(kind, supplemental.Selection(kind))
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Set up {title.lower()}")
        dialog.setMinimumWidth(590)
        content = layout(dialog)
        content.setContentsMargins(14, 14, 14, 14)
        message = {
            "disk-image": "Choose a saved raw disk image (.dd, .img or .raw) from your imaging tool or IT team.",
            "memory-capture": "Choose a saved raw memory dump (.raw or .mem) from your incident responder.",
            "endpoint-telemetry": "Choose a Microsoft Defender XDR DeviceEvents export in CSV format.",
            "identity-activity": "Choose a Microsoft Entra sign-in export in JSON format.",
            "network-evidence": "Choose a saved network capture (.pcap or .pcapng) from Wireshark or your IT team.",
        }[kind]
        source_example = {
            "disk-image": "For example, a disk serial or OFFICE-PC-07",
            "memory-capture": "For example, OFFICE-PC-07",
            "endpoint-telemetry": "For example, the company Defender tenant or device name",
            "identity-activity": "For example, the company Entra tenant name",
            "network-evidence": "For example, HQ firewall or the sensor name",
        }[kind]
        content.addWidget(readable(message, "caption"))
        content.addWidget(readable("For a saved file, only Evidence file is required.", "caption"))

        def file_picker(field, label, file_filter):
            def browse():
                selected, _ = QFileDialog.getOpenFileName(dialog, f"Select {label.lower()}", "", file_filter)
                if selected:
                    field.setText(selected)
            row = QWidget()
            controls = QHBoxLayout(row)
            controls.setContentsMargins(0, 0, 0, 0)
            controls.addWidget(field, 1)
            button = self.button("Browse…", browse)
            button.setAccessibleName(f"Browse for {label.lower()}")
            controls.addWidget(button)
            return row

        evidence = self.path_entry("Evidence file", "Browse for the file you received or exported")
        evidence.setText(saved.path)
        extensions = " ".join("*." + ext for ext in sorted(bundle.ATTACHMENT_TYPES[kind]))
        file_form = QFormLayout()
        file_form.addRow("Evidence file", file_picker(evidence, "Evidence file", f"Evidence files ({extensions})"))
        content.addLayout(file_form)

        details = QWidget()
        details_form = layout(details)
        form = QFormLayout()
        fields = {
            "checksum": ("SHA-256 checksum file", "Select the checksum file supplied separately with the evidence",
                         "A checksum is a fingerprint. Use the .sha256 or .txt file supplied by a trusted source to check for changes."),
            "source": ("Source or device ID", source_example,
                       "The computer, disk, account system or sensor the evidence came from. Use its known name or ID."),
            "tool": ("Tool and version", "For example, Wireshark 4.4",
                     "The name and version of the program that captured or exported the file. Check its report or About screen."),
            "operator": ("Operator", "For example, Ayesha Khan",
                         "The person who captured or exported the file. Enter your name if you performed that work."),
            "captured": ("Acquired time", "For example, 2026-11-12T14:30:00+05:00",
                         "When the file was captured or exported, including the timezone. Copy the recorded time and offset."),
            "notes": ("Custody notes", "For example, received from IT in ticket IR-024",
                      "How you received the file and any known gaps or limits. Enter one short line."),
        }
        entries = {"path": evidence}
        for key, (label, placeholder, help_text) in fields.items():
            entry = self.path_entry(label, placeholder)
            entry.setToolTip(help_text)
            entry.setAccessibleDescription(help_text)
            entry.setText(getattr(saved, key))
            if key == "checksum":
                form.addRow(label, file_picker(entry, label, "Checksums (*.sha256 *.txt)"))
            else:
                entry.setMaxLength(500)
                form.addRow(label, entry)
            entries[key] = entry

        offline = [saved.offline]
        details_note = readable("", "caption")
        details_form.addWidget(details_note)
        details_form.addLayout(form)
        toggle = QPushButton("Show optional details")
        toggle.setCheckable(True)

        def show_details(visible):
            details.setVisible(visible)
            toggle.setText("Hide optional details" if visible else "Show optional details")
            dialog.adjustSize()

        def update_offline():
            details_note.setText(
                "The offline record requires a checksum file, tool and version, operator, and acquired time."
                if offline[0] else "Use details supplied with the file. Leave fields blank if you do not know.")

        if kind == "disk-image":
            def offline_details():
                offline[0] = self.offline_imaging(dialog, offline[0])
                receipt_status.setText("Offline acquisition details entered." if offline[0] else "Using an existing image.")
                update_offline()
                if offline[0]:
                    toggle.setChecked(True)
            receipt_status = readable("Offline acquisition details entered." if saved.offline else "Using an existing image.",
                                      "caption")
            self.row(content, self.button("Offline imaging guide and record…", offline_details), receipt_status)
        content.addWidget(toggle)
        content.addWidget(details)
        toggle.toggled.connect(show_details)
        update_offline()
        toggle.setChecked(bool(saved.offline or any(getattr(saved, key) for key in fields)))
        details.setVisible(toggle.isChecked())
        error = readable("", "status")
        content.addWidget(error)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        def save():
            item = supplemental.Selection(kind, **{key: entry.text().strip() for key, entry in entries.items()},
                                          offline=offline[0])
            try:
                validated, = supplemental.validate((item,))
                if validated.size is None:
                    raise Invalid("Choose an existing evidence file or select Cancel.")
                supplemental.file_size(Path(validated.path), kind)
                self.evidence_files[kind] = validated
            except (Invalid, OSError) as exc:
                error.setText(str(exc))
            else:
                dialog.accept()
        buttons.accepted.connect(save)
        buttons.rejected.connect(dialog.reject)
        content.addWidget(buttons)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.status(f"{title} setup saved for this collection.")

    def offline_imaging(self, parent, prior):
        dialog = QDialog(parent)
        dialog.setWindowTitle("Record offline disk acquisition")
        dialog.resize(630, 420)
        body = layout(dialog)
        body.setContentsMargins(14, 14, 14, 14)
        body.addWidget(readable(
            "Use a dedicated acquisition workstation and verify the source disk identity. Connect it through a "
            "verified hardware write blocker. Write the raw image to a separate disk with an approved signed tool. "
            "Record its SHA-256 independently, then return here with the completed image.", "caption"))
        form = QFormLayout()
        names = (
            ("source_device", "Source disk ID", "Serial or ID of the disk being copied"),
            ("output_device", "Output disk ID", "Serial or ID of the separate destination disk"),
            ("write_blocker", "Write blocker ID", "Serial or equipment label on the verified write blocker"),
            ("sector_bytes", "Source sector size in bytes", "Copy the value from the report, such as 512 or 4096"),
            ("source_bytes", "Source size in bytes", "Copy the exact byte count from the report"),
            ("read_errors", "Reported read errors", "Copy the count. Use 0 only if the report says none."),
        )
        fields = {}
        for key, title, placeholder in names:
            entry = self.path_entry(title, placeholder)
            entry.setMaxLength(150)
            entry.setText(str(getattr(prior, key)) if prior else "")
            entry.setToolTip(placeholder)
            entry.setAccessibleDescription(placeholder)
            form.addRow(title, entry)
            fields[key] = entry
        body.addLayout(form)
        confirmed = QCheckBox("The operator verified the write blocker and separate output disk.")
        confirmed.setChecked(bool(prior and prior.operator_verified))
        body.addWidget(confirmed)
        error = readable("", "status")
        body.addWidget(error)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel |
                                   QDialogButtonBox.StandardButton.Reset)
        result = [prior]
        def save():
            values = {key: entry.text().strip() for key, entry in fields.items()}
            try:
                for key in ("sector_bytes", "source_bytes", "read_errors"):
                    values[key] = int(values[key])
            except ValueError:
                error.setText("Enter a whole number for sector size, source size and read errors.")
                return
            receipt = supplemental.OfflineReceipt(**values, operator_verified=confirmed.isChecked())
            try:
                supplemental.validate_receipt(receipt)
            except Invalid as exc:
                error.setText(str(exc))
                return
            result[0] = receipt
            dialog.accept()
        def reset():
            result[0] = None
            dialog.accept()
        buttons.accepted.connect(save)
        buttons.rejected.connect(dialog.reject)
        buttons.button(QDialogButtonBox.StandardButton.Reset).clicked.connect(reset)
        body.addWidget(buttons)
        dialog.exec()
        return result[0]

    def update_profile(self, mode):
        descriptions = {
            "Quick": "Capture recent System and Application events, running processes and network activity.",
            "Standard": "Include Windows Security, Defender, PowerShell, accounts, startup and system inventory.",
            "Extended": "Add operational logs and network context. Choose any extra file or command-line scope explicitly.",
            "Custom": "Choose the exact event channels and collectors for an authorized capture.",
        }
        self.profile_help.setText(descriptions[mode])
        self.hours.setMaximum(168 if mode in {"Extended", "Custom"} else 24)
        self.custom_collectors.setEnabled(mode == "Custom")
        self.custom_channels.setEnabled(mode == "Custom")
        for control in (self.process_args, self.hash_files, self.select_files, self.clear_files):
            control.setEnabled(mode in {"Extended", "Custom"})

    def reset_files(self):
        self.chosen_files = []
        self.hash_files.setChecked(False)
        self.status("File selection cleared.")

    def pick_files(self):
        selected, _ = QFileDialog.getOpenFileNames(self, "Select authorized evidence files")
        if selected:
            self.chosen_files = selected
            self.status(f"Selected {len(selected)} local files.")

    def pick_output(self):
        path = QFileDialog.getExistingDirectory(self, "Choose the collection output directory")
        if path:
            self.output.setText(path)

    def discover_channels(self):
        self.start(lambda cancel, _: native.channels(cancel), self.select_channels)

    def select_channels(self, channels):
        dialog = QDialog(self)
        dialog.setWindowTitle("Choose Windows event logs")
        dialog.resize(625, 475)
        content = layout(dialog)
        content.setContentsMargins(14, 14, 14, 14)
        content.addWidget(readable("Select up to 24 installed logs to add to the Custom profile.", "caption"))
        choices = QListWidget()
        choices.setAccessibleName("Installed Windows event channels")
        choices.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        choices.addItems(channels)
        prior = {name.strip() for name in self.custom_channels.text().split(",")}
        for index, name in enumerate(channels):
            if name in prior:
                choices.item(index).setSelected(True)
        content.addWidget(choices, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        content.addWidget(buttons)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            selected = [item.text() for item in choices.selectedItems()]
            if len(selected) > 24:
                self.status("Choose at most 24 event channels.")
                return
            self.profile.setCurrentText("Custom")
            self.custom_channels.setText(", ".join(selected))
            self.status(f"Selected {len(selected)} Windows event channels.")

    def get_plan(self):
        if not self.output.text().strip():
            raise Invalid("Choose a local output directory")
        profile = self.profile.currentText().lower()
        custom = profile == "custom"
        advanced = custom or profile == "extended"
        evidence = tuple(self.evidence_files.get(kind, supplemental.Selection(kind))
                         for kind, control in self.evidence_choices.items() if control.isChecked())
        return collect.plan(profile, self.output.text(), hours=self.hours.value(),
                            collectors=[s.strip() for s in self.custom_collectors.text().split(",") if s.strip()] if custom else (),
                            channels=[s.strip() for s in self.custom_channels.text().split(",") if s.strip()] if custom else (),
                            files=self.chosen_files if advanced else (),
                            hash_files=advanced and self.hash_files.isChecked(),
                            process_arguments=advanced and self.process_args.isChecked(), max_rows=self.rows_limit.value(),
                            evidence=evidence)

    def show_plan(self):
        def show():
            self.present_view(self.capture_detail, "plan", asdict(self.get_plan()))
            self.status("Scope preview ready.")
        self.guarded(show)

    def start_collection(self):
        def start():
            scope = self.get_plan()
            self.present_view(self.capture_detail, "plan", asdict(scope))
            text = ("Collect the displayed scope from this Windows host? Evidence may contain private information.\n\n"
                    + "\n".join(scope.sensitive))
            if QMessageBox.question(self, "Confirm authorized collection", text) != QMessageBox.StandardButton.Yes:
                return
            self.collection_folder = scope.destination
            self.start(lambda cancel, progress: collect.run(scope, cancel, progress), self.show_collection_result)
        self.guarded(start)

    def show_collection_result(self, result):
        self.last_bundle = result["archive"]
        self.last_checksum = result["checksum"]
        self.open_capture.setEnabled(True)
        self.present_view(self.capture_detail, "capture", {
            "archive": self.last_bundle, "checksum": result["checksum"],
            "coverage": result["manifest"]["attempts"]
        })
        partial = any(item["status"] != "Collected" for item in
                      {a["collector"]: a for a in result["manifest"]["attempts"]}.values())
        self.status("Collection finished with source gaps. Review coverage." if partial else
                    "Collection finished. Open the evidence in a case to begin reviewing it.")

    def open_last_capture(self):
        self.nav.setCurrentRow(CASE_PAGE)
        self.show_import_form(self.last_bundle)
        self.import_hash.setText(self.last_checksum)

    def retry_collection(self):
        if not self.last_bundle:
            self.status("Run a collection with eligible denied Windows events first.")
            return
        if QMessageBox.question(self, "Retry denied event sources",
                                "Retry eligible denied Windows event sources with administrator access?") != QMessageBox.StandardButton.Yes:
            return
        from .elevation import retry
        self.start(lambda cancel, progress: retry(self.last_bundle, self.collection_folder, cancel, progress),
                   self.show_collection_result)

    def case_page(self, body):
        self.case_label = readable("Open a case folder or import a collection ZIP. Add a saved EVTX if you have an extra log.",
                                   "status")
        body.addWidget(self.case_label)
        self.row(body, self.button("Import evidence…", self.show_import_form, "Ctrl+I"),
                 self.button("Open case…", self.open_case),
                 self.button("Verify ZIP…", self.show_import_form),
                 self.button("Coverage", self.show_coverage))
        self.import_form = QWidget()
        intake = layout(self.import_form)
        self.import_zip = self.path_entry("Evidence file", "Local Windows Traige ZIP or saved EVTX")
        self.import_case = self.path_entry("Case folder", "Case folder path, with an existing parent")
        self.import_hash = self.path_entry("Detached SHA-256 file", "Optional trusted detached SHA-256 file")
        self.row(intake, self.import_zip, self.button("Browse for evidence…", self.pick_import_zip))
        intake.addWidget(self.import_case)
        intake.addWidget(self.import_hash)
        self.row(intake, self.button("Verify and import", self.import_selected), self.button("Verify ZIP only", self.verify_selected),
                 self.button("Open existing case", self.open_entered_case),
                 self.button("Close import", self.import_form.hide))
        body.addWidget(self.import_form)
        self.import_form.hide()
        self.search = QLineEdit()
        self.search.setAccessibleName("Search evidence")
        self.search.setPlaceholderText("Search evidence")
        self.search.returnPressed.connect(self.apply_query)
        self.event_id = QLineEdit()
        self.event_id.setAccessibleName("Event ID filter")
        self.event_id.setPlaceholderText("Event ID")
        self.event_id.setMaximumWidth(92)
        self.event_id.returnPressed.connect(self.apply_query)
        self.kind = QComboBox()
        self.kind.setAccessibleName("Evidence type filter")
        self.kind.addItems(["All evidence", *sorted(bundle.KINDS)])
        self.kind.currentIndexChanged.connect(self.apply_query)
        self.row(body, self.search, self.event_id, self.kind, self.button("Filter", self.apply_query),
                 self.button("More filters…", self.advanced))
        self.local_time = QCheckBox("Display local time")
        self.local_time.toggled.connect(self.populate_rows)
        self.row(body, self.local_time, self.button("Save filter…", self.save_view),
                 self.button("Load filter…", self.load_view))
        split = QSplitter()
        self.table = QTableWidget(0, 4)
        self.table.setAccessibleName("Case evidence timeline")
        self.table.setHorizontalHeaderLabels(["Observed UTC", "Type", "Summary", "Source"])
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        for column, width in enumerate((151, 74, 167)):
            self.table.setColumnWidth(column, width)
        self.table.currentCellChanged.connect(self.show_record)
        split.addWidget(self.table)
        self.details = editor("Evidence provenance and details", True)
        self.details.setPlainText("Select a record to see its archive, source and timestamps.")
        split.addWidget(self.details)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        split.setSizes([580, 345])
        body.addWidget(split, 1)
        self.previous = self.button("Previous page", lambda: self.page_by(-100))
        self.next = self.button("Next page", lambda: self.page_by(100))
        self.row(body, self.previous, self.next, self.button("Native event", self.show_native_event),
                 self.button("Save original…", self.save_original), self.button("Add annotation…", self.annotate),
                 self.button("Use in Assistant", self.add_excerpt))

    def open_case(self):
        path = QFileDialog.getExistingDirectory(self, "Open a case folder containing case.sqlite3")
        if path:
            self.set_case(path)

    def set_case(self, path):
        def opened():
            case.coverage(path)
            self.case_path = path
            self.disconnect_ai()
            self.offset = 0
            self.refresh_case()
        self.guarded(opened)

    def path_entry(self, name, placeholder):
        field = QLineEdit()
        field.setAccessibleName(name)
        field.setPlaceholderText(placeholder)
        return field

    def show_import_form(self, initial=None):
        self.nav.setCurrentRow(CASE_PAGE)
        self.import_form.show()
        if self.case_path:
            self.import_case.setText(self.case_path)
        if isinstance(initial, str):
            self.import_zip.setText(initial)
        self.import_zip.setFocus()

    def open_entered_case(self):
        path = self.import_case.text().strip()
        if path:
            self.set_case(path)
        else:
            self.status("Enter the folder for an existing case.")

    def verify_selected(self):
        archive = self.import_zip.text().strip()
        sidecar = self.import_hash.text().strip() or None
        if Path(archive).suffix.lower() != ".zip":
            self.status("Verify ZIP only checks Windows Traige ZIPs. To check a saved EVTX, choose Verify and import.")
            return
        self.start(lambda cancel, _: bundle.verify(archive, sidecar, cancel), self.verified)

    def pick_import_zip(self):
        selected = QFileDialog.getOpenFileName(self, "Select a local evidence file", "",
                                               "Evidence files (*.zip *.evtx)")[0]
        if selected:
            self.import_zip.setText(selected)

    def import_selected(self):
        archive = self.import_zip.text().strip()
        target = self.import_case.text().strip()
        checksum = self.import_hash.text().strip() or None
        if not archive or not target:
            self.status("Enter a local ZIP or saved EVTX and a case folder path.")
            return

        def done(result):
            if target != self.case_path:
                self.disconnect_ai()
            self.case_path = target
            self.import_form.hide()
            self.refresh_case()
            count = result.get("records", 0)
            word = "Evidence already in this case" if result["duplicate"] else f"Imported {summary.quantity(count, 'record')}"
            source = result.get("source_evidence")
            digest = (f"Original EVTX SHA-256 {source['external']}" if source else
                      f"Detached ZIP SHA-256 {result['verification']['external']}")
            self.status(f"{word}. {digest}.")
        self.start(lambda cancel, progress: case.import_evidence(target, archive, checksum, cancel, progress), done)

    def verified(self, result):
        self.import_form.hide()
        self.present_view(self.details, "verification", result)
        self.status(f"Internal consistency verified. Detached SHA-256 {result['external']}.")

    def show_coverage(self):
        if self.case_path:
            self.guarded(lambda: self.present_view(self.details, "coverage", case.coverage(self.case_path)))
        else:
            self.status("Open or import a case to see its coverage.")

    def refresh_case(self):
        self.case_label.setText(f"Case folder  {Path(self.case_path).name}")
        self.case_summary = None
        self.summary_leads.clear()
        self.summary_open.setEnabled(False)
        self.clear_view(self.summary_output, "Open Evidence Summary or click Refresh summary to review this case.")
        self.apply_query()

    def criteria(self):
        event = self.event_id.text().strip()
        if event and not event.isdecimal():
            raise Invalid("Enter a numeric event ID")
        return dict(self.extra, kind=self.kind.currentText() if self.kind.currentIndex() else None,
                    event_id=int(event) if event else None, text=self.search.text().strip() or None,
                    offset=self.offset, limit=100)

    def apply_query(self, *_):
        self.offset = 0
        self.run_query()

    def page_by(self, step):
        self.offset = max(0, self.offset + step)
        self.run_query()

    def run_query(self):
        if self.case_path:
            def loaded():
                self.rows = case.query(self.case_path, **self.criteria())
                self.populate_rows()
                self.status(f"Displayed {len(self.rows)} records from offset {self.offset}.")
            self.guarded(loaded)

    def populate_rows(self, *_):
        self.table.setRowCount(0)
        self.table.setRowCount(len(self.rows))
        use_local = self.local_time.isChecked()
        self.table.setHorizontalHeaderItem(0, QTableWidgetItem("Observed local" if use_local else "Observed UTC"))
        for idx, item in enumerate(self.rows):
            fields = item["fields"]
            time = item["observed"]
            display = (datetime.fromisoformat(time).astimezone().isoformat(timespec="seconds") if use_local else
                       time[:19].replace("T", " ")) if time else "Unknown"
            if item["kind"] == "event":
                summary = f"{fields.get('channel', '')} · {fields.get('action') or fields.get('event_id', '')}"
            else:
                summary = str(fields.get("path") or fields.get("remote_ip") or fields.get("filename")
                              or fields.get("Name") or item["id"])
            for column, value in enumerate((display, item["kind"], summary, item["host"])):
                self.table.setItem(idx, column, QTableWidgetItem(value))
        self.previous.setEnabled(self.offset > 0)
        self.next.setEnabled(len(self.rows) == 100)
        self.clear_view(self.details, "Select a record to see its archive, source and timestamps." if self.rows else
                        "No records match. Clear filters or check the imported coverage.")

    def show_record(self, row, *_):
        if 0 <= row < len(self.rows):
            item = self.rows[row]
            self.guarded(lambda: self.present_view(self.details, "record", {
                "record": item, "process_links": case.correlate(self.case_path, item)
            }))

    def show_native_event(self):
        row = self.selected_row()
        if not row:
            self.status("Select an event record.")
            return
        active_case = self.case_path
        self.start(lambda cancel, _: case.native_event(active_case, row["archive"], row["id"], cancel),
                   lambda value: (self.clear_view(self.details, value), self.status("Read the referenced EVTX record locally.")))

    def save_original(self):
        row = self.selected_row()
        if not row or not row["source"].startswith("attachments/"):
            self.status("Select a record backed by a supplemental original.")
            return
        name = Path(row["source"]).name
        suffix = Path(name).suffix
        destination = QFileDialog.getSaveFileName(self, "Save a verified working copy", name,
                                                  f"Evidence file (*{suffix})")[0]
        if destination:
            active_case = self.case_path
            self.start(lambda cancel, _: case.export_original(active_case, row["archive"], row["id"], destination, cancel),
                       lambda result: self.status(f"Saved a verified working copy. SHA-256 {result['sha256']}."))

    def advanced(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Evidence filters")
        form = QFormLayout(dialog)
        fields = {}
        for key, label in (("channel", "Channel"), ("severity", "Severity"), ("pid", "PID"),
                           ("path", "Executable path"), ("ip", "IP"), ("port", "Port"),
                           ("start", "Start time with UTC offset"), ("end", "End time with UTC offset"),
                           ("archive", "Archive SHA-256")):
            field = QLineEdit(str(self.extra.get(key) or ""))
            form.addRow(label, field)
            fields[key] = field
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            try:
                self.extra = {key: int(field.text()) if key in {"pid", "port"} else field.text().strip()
                              for key, field in fields.items() if field.text().strip()}
            except ValueError:
                self.status("Use numeric values for PID and port.")
                return
            self.apply_query()

    def save_view(self):
        if not self.case_path:
            return
        name, ok = QInputDialog.getText(self, "Save filter", "Name")
        if ok:
            self.guarded(lambda: (case.save_filter(self.case_path, name, self.criteria()), self.status("Filter saved.")))

    def load_view(self):
        if self.case_path:
            def load():
                views = case.saved_filters(self.case_path)
                if not views:
                    self.status("No saved filters.")
                    return
                name, ok = QInputDialog.getItem(self, "Load saved filter", "Filter", list(views), editable=False)
                if ok:
                    saved = views[name]
                    self.extra = {key: value for key, value in saved.items()
                                  if key not in {"kind", "event_id", "text", "offset", "limit"}}
                    self.kind.setCurrentText(saved.get("kind") or "All evidence")
                    self.event_id.setText(str(saved["event_id"]) if saved.get("event_id") is not None else "")
                    self.search.setText(saved.get("text") or "")
                    self.apply_query()
            self.guarded(load)

    def selected_row(self):
        row = self.table.currentRow()
        return self.rows[row] if 0 <= row < len(self.rows) else None

    def annotate(self):
        row = self.selected_row()
        if not row:
            self.status("Select an evidence record.")
            return
        kind, ok = QInputDialog.getItem(self, "Annotate record", "Type", ["note", "bookmark", "finding", "hypothesis"],
                                        editable=False)
        if not ok:
            return
        value, ok = QInputDialog.getMultiLineText(self, "Annotate record", "Annotation text")
        if ok:
            self.guarded(lambda: (case.annotate(self.case_path, row["archive"], row["id"], kind, value,
                                                 self.author.text()), self.status("Annotation saved.")))

    def report_page(self, body):
        self.author = QLineEdit()
        self.author.setAccessibleName("Operator identity")
        self.author.setPlaceholderText("Optional operator identity for annotations and reviews")
        body.addWidget(self.author)
        self.row(body, self.button("Refresh annotations", self.refresh_findings),
                 self.button("Mark finding reviewed…", self.review_finding),
                 self.button("Choose report path…", self.choose_report))
        self.report_path = self.path_entry("Report output path", "Full output path ending in .html, .json, or .csv")
        self.row(body, self.report_path, self.button("Export report", self.export_report))
        self.selected_only = QCheckBox("Export only the selected record")
        body.addWidget(self.selected_only)
        self.findings = editor("Case annotations and findings", True)
        body.addWidget(self.findings, 1)

    def refresh_findings(self):
        if self.case_path:
            self.guarded(lambda: self.present_view(self.findings, "findings", case.annotations(self.case_path)))
        else:
            self.clear_view(self.findings, "Open a case to see annotations and findings.")

    def summary_page(self, body):
        self.summary_leads = QComboBox()
        self.summary_leads.setAccessibleName("Evidence summary review leads")
        self.summary_leads.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.summary_leads.setMinimumContentsLength(18)
        self.summary_open = self.button("Open highlighted record", self.open_summary_lead)
        self.summary_open.setEnabled(False)
        self.row(body, self.button("Refresh summary", self.refresh_summary), self.summary_leads, self.summary_open)
        self.summary_path = self.path_entry("Summary output path", "Full local output path ending in .txt")
        self.row(body, self.summary_path, self.button("Browse…", self.choose_summary_path),
                 self.button("Save summary", self.export_summary))
        self.summary_output = editor("Evidence summary and recommended next steps", True)
        self.summary_output.setPlainText("Open a case to see what the evidence says and review next steps.")
        body.addWidget(self.summary_output, 1)

    def refresh_summary(self):
        if not self.case_path:
            self.clear_view(self.summary_output, "Open a case to see what the evidence says and review next steps.")
            return
        current = self.case_path

        def ready(result):
            if self.case_path != current:
                return
            self.case_summary = result
            self.present_view(self.summary_output, "summary", result)
            self.summary_leads.clear()
            for item in result["highlights"]:
                self.summary_leads.addItem(f"{item['channel']} {item['event_id']} · {item['title']}", item)
            if not result["highlights"]:
                self.summary_leads.addItem("No highlighted event")
            self.summary_open.setEnabled(bool(result["highlights"]))
            self.status("Evidence summary ready.")

        self.start(lambda *_: summary.build(current), ready)

    def show_referenced_record(self, identity, ref):
        row = case.get_record(self.case_path, identity, ref)
        self.nav.setCurrentRow(CASE_PAGE)
        self.rows, self.offset = [row], 0
        self.populate_rows()
        self.table.setCurrentCell(0, 0)
        self.show_record(0)

    def open_summary_lead(self):
        lead = self.summary_leads.currentData()
        if lead and self.case_summary:
            self.guarded(lambda: self.show_referenced_record(lead["digest"], lead["ref"]))

    def choose_summary_path(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save plain-language evidence summary", "evidence-summary.txt",
                                              "Plain text (*.txt)")
        if path:
            self.summary_path.setText(path)

    def export_summary(self):
        def save():
            if not self.case_summary:
                raise Invalid("Open a case and refresh the evidence summary first")
            path = self.summary_path.text().strip()
            if not path:
                raise Invalid("Choose a local .txt output path")
            summary.export(self.case_summary, path)
            self.status(f"Saved the evidence summary to {Path(path).name}.")
        self.guarded(save)

    def review_finding(self):
        if self.case_path:
            ident, ok = QInputDialog.getInt(self, "Review finding", "Annotation ID", 1, 1)
            if ok:
                self.guarded(lambda: (case.review(self.case_path, ident, self.author.text()), self.refresh_findings(),
                                      self.status("Finding reviewed.")))

    def choose_report(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export case material", "case-report.html",
                                              "HTML (*.html);;JSON (*.json);;CSV (*.csv)")
        if path:
            self.report_path.setText(path)

    def export_report(self):
        if not self.case_path:
            self.status("Open a case first.")
            return
        path = self.report_path.text().strip()
        if not path:
            self.status("Enter a local report output path.")
            return

        def export_selected():
            row = self.selected_row()
            if self.selected_only.isChecked() and not row:
                raise Invalid("Select a record before exporting")
            selected = [row] if self.selected_only.isChecked() else None
            case_path, criteria = self.case_path, self.criteria()
            self.start(lambda *_: report.export(case_path, path, criteria, selected),
                       lambda result: self.status(f"Exported {result['records']} records to {Path(path).name}."))
        self.guarded(export_selected)

    def ai_page(self, body):
        self.ai_enabled = QCheckBox("Enable network AI for this session")
        self.ai_enabled.toggled.connect(self.ai_state)
        self.provider = QComboBox()
        for key, name in assistant.PROVIDER_NAMES.items():
            self.provider.addItem(name, key)
        self.provider.setAccessibleName("AI provider")
        self.model = QComboBox()
        self.model.setAccessibleName("AI model")
        self.model.setToolTip("A model is the service that generates replies. Pick a named option or use an exact ID.")
        self.manual_model = self.path_entry("Manual model ID", "Enter the exact model ID from the provider")
        self.manual_model.hide()
        self.model.currentIndexChanged.connect(lambda: self.manual_model.setVisible(self.model.currentIndex() >= 0
                                                                                  and self.model.currentData() is None))
        self.key = QLineEdit()
        self.key.setAccessibleName("Session API credential")
        self.key.setEchoMode(QLineEdit.EchoMode.Password)
        self.key.setPlaceholderText("Session-only API credential")
        self.tools = QCheckBox("Allow case tools")
        self.tools.setChecked(True)
        self.overview = QCheckBox("Include case overview")
        self.overview.setToolTip("Share record counts, collection gaps and up to eight redacted review leads after approval.")
        self.legacy = QCheckBox("OpenAI legacy text interface")
        self.legacy.hide()
        setup = QWidget()
        connection = layout(setup)
        self.ai_setup = QPushButton("Hide connection setup")
        self.ai_setup.setCheckable(True)
        self.ai_setup.setChecked(True)
        self.ai_setup.toggled.connect(setup.setVisible)
        self.ai_setup.toggled.connect(lambda visible: self.ai_setup.setText(
            "Hide connection setup" if visible else "Show connection setup"))
        self.row(body, self.ai_enabled, self.ai_setup, self.button("Disconnect", self.disconnect_ai))
        body.addWidget(setup)
        self.row(connection, self.provider, self.model, self.button("Check key and list models", self.discover_models))
        connection.addWidget(self.manual_model)
        self.row(connection, self.key, self.button("Load key from file…", self.import_key))
        self.row(connection, self.button("Load saved key", self.load_key),
                 self.button("Save key…", self.save_key), self.button("Forget saved key…", self.forget_key))
        self.row(body, self.tools, self.overview, self.legacy, self.button("Clear attached records", self.clear_excerpts))
        self.proposal_button = self.button("Review proposed action…", self.review_proposal)
        self.proposal_button.setEnabled(False)
        self.row(body, self.proposal_button, self.button("New chat", self.clear_chat))
        self.ai_output = editor("Assistant conversation", True)
        body.addWidget(self.ai_output, 1)
        self.question = editor("Message to the assistant")
        self.question.setMaximumHeight(68)
        self.question.setPlaceholderText("Ask for help or a follow-up. Use Ctrl+Enter to review and send.")
        self.send_chat = self.button("Review and send…", self.ask_assistant, "Ctrl+Return")
        self.row(body, self.question, self.send_chat)
        self.provider.currentIndexChanged.connect(self.provider_changed)
        self.fill_models()
        self.refresh_chat()

    def provider_changed(self, *_):
        if self.session:
            self.session.disconnect()
            self.session = None
            self.cancel_current()
        self.clear_chat()
        self.fill_models()
        self.legacy.setVisible(self.provider.currentData() == "openai")
        self.key.clear()

    def fill_models(self, rows=()):
        provider = self.provider.currentData()
        current = self.model.currentData()
        preferred = assistant.PRESETS[provider]
        names = {model: name for name, model in preferred}
        for row in rows:
            if row["text"] and row["id"] not in names:
                names[row["id"]] = row["name"] if isinstance(row["name"], str) else row["id"]
        self.model.clear()
        for ident, name in names.items():
            self.model.addItem(name if name == ident else f"{name} · {ident}" if ident not in dict(preferred).values() else name,
                               ident)
        self.model.addItem("Enter model ID manually…")
        index = self.model.findData(current) if current else 0
        self.model.setCurrentIndex(max(0, index))

    def clear_excerpts(self):
        self.disclosed.clear()
        self.overview.setChecked(False)
        self.status("Attached evidence cleared.")

    def clear_chat(self):
        self.chat_history = []
        self.last_answer = None
        self.pending_chat = None
        self.proposals = []
        self.proposal_button.setEnabled(False)
        if self.session:
            self.session.pending.clear()
        self.refresh_chat()

    def ai_state(self, enabled):
        if not enabled:
            self.disconnect_ai()
        else:
            self.status("AI enabled for this session. Network use requires a provider action.")

    def disconnect_ai(self):
        if self.session:
            self.session.disconnect()
            self.session = None
            self.cancel_current()
        if self.ai_enabled.isChecked():
            self.ai_enabled.blockSignals(True)
            self.ai_enabled.setChecked(False)
            self.ai_enabled.blockSignals(False)
        self.key.clear()
        self.disclosed.clear()
        self.overview.setChecked(False)
        self.clear_chat()
        self.status("AI is off.")

    def make_session(self, model):
        if not self.ai_enabled.isChecked():
            raise Invalid("Enable AI explicitly for this session")
        provider = self.provider.currentData()
        return assistant.Session(provider, model, self.key.text(),
                                 legacy_openai=provider == "openai" and self.legacy.isChecked())

    def import_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load an API key for this session", "", "Text files (*.txt);;All files (*)")
        if path:
            self.guarded(lambda: (self.key.setText(credentials.from_file(self.provider.currentData(), path)),
                                  self.status("API key loaded for this session.")))

    def load_key(self):
        self.guarded(lambda: (self.key.setText(credentials.load(self.provider.currentData())),
                              self.status("Loaded the provider credential into the masked field.")))

    def save_key(self):
        provider = self.provider.currentData()
        if QMessageBox.question(self, "Save provider credential",
                                "Save this provider key to Windows Credential Manager for this user?") == QMessageBox.StandardButton.Yes:
            self.guarded(lambda: (credentials.save(provider, self.key.text().strip()),
                                  self.status("Provider credential saved to Windows Credential Manager.")))

    def forget_key(self):
        provider = self.provider.currentData()
        if QMessageBox.question(self, "Forget provider credential",
                                "Remove the saved key for the selected provider?") == QMessageBox.StandardButton.Yes:
            self.guarded(lambda: (credentials.delete(provider), self.status("Saved provider credential removed.")))

    def discover_models(self):
        def discover():
            session = self.make_session("")
            self.session = session
            self.start(lambda cancel, _: session.discover(cancel), self.models_found)
        self.guarded(discover)

    def models_found(self, rows):
        self.fill_models(rows)
        self.status(f"Key accepted. Found {sum(row['text'] is True for row in rows)} text-capable model entries.")

    def add_excerpt(self):
        row = self.selected_row()
        if not row:
            self.status("Select a record first.")
            return
        ref = f"{row['archive']}/{row['id']}"
        if ref not in self.disclosed and len(self.disclosed) < 8:
            self.disclosed.append(ref)
        self.status(f"{len(self.disclosed)} record excerpts queued for review.")

    def ask_assistant(self):
        def ask():
            if self.thread:
                raise Invalid("Wait for the current operation to finish")
            model = self.model.currentData() or self.manual_model.text().strip()
            if not model:
                raise Invalid("Choose a model or enter an exact model ID")
            session = self.make_session(model)
            case_path = self.case_path
            question = self.question.toPlainText().strip()
            if not 1 <= len(question) <= 4000:
                raise Invalid("Enter a message of 1 to 4,000 characters")
            tools = bool(case_path and self.tools.isChecked() and not session.legacy_openai)
            refs = list(self.disclosed) if case_path else []
            overview = None
            if case_path and self.overview.isChecked():
                result = self.case_summary or summary.build(case_path)
                overview = {"records": result["records"], "source_statuses": result["coverage"],
                            "review_leads": [{key: entry[key] for key in ("event_id", "channel", "count")}
                                             for entry in result["highlights"]]}
                refs = list(dict.fromkeys(refs + [entry["digest"] + "/" + entry["ref"]
                                                 for entry in result["highlights"]]))[:8]
            excerpts = assistant.preview(case_path, refs)
            history = [{"speaker": item["speaker"], "text": item["text"][:1800]} for item in self.chat_history[-8:]]
            confirmation = QDialog(self)
            confirmation.setWindowTitle("Approve provider disclosure")
            confirmation.resize(600, 400)
            content = layout(confirmation)
            content.setContentsMargins(12, 12, 12, 12)
            preview = editor("Outbound disclosure preview", True)
            disclosure = {"provider": assistant.PROVIDER_NAMES[session.provider], "model": session.model,
                          "message": question, "case_tools": tools, "previous_chat": history,
                          "case_overview": overview, "evidence_excerpts": excerpts}
            preview.setPlainText(present.format_view("generic", disclosure, self.view_mode.currentIndex() == 1))
            content.addWidget(preview)
            choices = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
            choices.button(QDialogButtonBox.StandardButton.Ok).setText("Send approved data")
            choices.accepted.connect(confirmation.accept)
            choices.rejected.connect(confirmation.reject)
            content.addWidget(choices)
            if confirmation.exec() != QDialog.DialogCode.Accepted:
                return
            self.session = session
            self.pending_chat = question
            self.refresh_chat()
            self.start(lambda cancel, _: session.ask(case_path, question, excerpts, tools, cancel,
                                                     history=history, overview=overview),
                       lambda result: self.show_answer(result) if self.session is session else None)
        self.guarded(ask)

    def show_answer(self, result):
        question = self.pending_chat
        if question is None:
            return
        self.pending_chat = None
        if self.question.toPlainText().strip() == question:
            self.question.clear()
        self.last_answer = result
        self.ai_setup.setChecked(False)
        self.chat_history.extend([{"speaker": "You", "text": question},
                                  {"speaker": "Assistant", "text": result["text"], "citations": result["citations"],
                                   "unresolved": result["unresolved"]}])
        self.chat_history = self.chat_history[-60:]
        self.proposals = result["proposals"]
        self.proposal_button.setEnabled(bool(self.proposals))
        self.refresh_chat()
        self.status("Assistant response received. Review evidence citations before use.")

    def refresh_chat(self):
        if self.view_mode.currentIndex() == 1 and self.last_answer is not None:
            self.ai_output.setPlainText(pretty(self.last_answer))
            return
        messages = []
        for item in self.chat_history:
            message = f"{item['speaker']}\n{item['text']}"
            if item.get("citations"):
                message += "\n\nEvidence cited\n" + "\n".join(item["citations"])
            if item.get("unresolved"):
                message += "\nSome cited references are outside the approved evidence."
            messages.append(message)
        if self.pending_chat:
            messages.append(f"You\n{self.pending_chat}\n\nWaiting for a reply…")
        if self.proposals:
            messages.append(f"{len(self.proposals)} local action proposals are ready to review.")
        self.ai_output.setPlainText("\n\n────────────\n\n".join(messages) or
                                    "Choose a provider and model, load your API key, then enable AI. "
                                    "You can ask how to use Windows Traige or share approved case excerpts.")
        scroll = self.ai_output.verticalScrollBar()
        scroll.setValue(scroll.maximum())

    def review_proposal(self):
        if not self.session or not self.proposals:
            return
        labels = [f"{proposal['operation']} ({proposal['id'][:8]})" for proposal in self.proposals]
        picked, accepted = QInputDialog.getItem(self, "Review a proposed action", "Action", labels, editable=False)
        if not accepted:
            return
        proposal = self.proposals[labels.index(picked)]
        approval = QDialog(self)
        approval.setWindowTitle("Confirm local action")
        approval.resize(570, 365)
        content = layout(approval)
        content.setContentsMargins(12, 12, 12, 12)
        content.addWidget(readable("Review the proposed operation and its arguments. "
                                   "Choose paths or confirm collection scope in the workbench.", "caption"))
        details = editor("Untrusted proposed action and exact arguments", True)
        details.setPlainText(present.format_view("generic", dict(proposal, case_folder=self.case_path),
                                                 self.view_mode.currentIndex() == 1))
        content.addWidget(details)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(approval.accept)
        buttons.rejected.connect(approval.reject)
        content.addWidget(buttons)
        confirmed = approval.exec() == QDialog.DialogCode.Accepted

        def apply():
            approved = self.session.consume(proposal["id"], self.case_path)
            self.proposals.remove(proposal)
            self.proposal_button.setEnabled(bool(self.proposals))
            operation, ref, value = (approved[key] for key in ("operation", "reference", "text"))
            case.audit_case(self.case_path, "assistant-proposal-review", {
                "provider": self.session.provider, "model": self.session.model, "action": operation,
                "reference": ref or None, "id": proposal["id"], "confirmation": "approved" if confirmed else "declined",
            })
            if not confirmed:
                return
            if operation == "collect":
                self.nav.setCurrentRow(COLLECTION_PAGE)
                self.profile.setCurrentText(value.title())
                self.status("Review and confirm the collection scope before starting.")
            elif operation == "report":
                self.nav.setCurrentRow(REPORTS_PAGE)
                self.status("Choose the output path and click Export report to confirm.")
            elif operation == "summary":
                self.nav.setCurrentRow(SUMMARY_PAGE)
            elif operation == "search":
                self.nav.setCurrentRow(CASE_PAGE)
                self.extra = {}
                self.kind.setCurrentIndex(0)
                numeric = value.isdecimal() and len(value) <= 5
                self.search.setText("" if numeric else value)
                self.event_id.setText(value if numeric else "")
                self.apply_query()
            else:
                self.nav.setCurrentRow(CASE_PAGE)
                if operation == "verify":
                    self.show_import_form()
                elif operation == "import":
                    self.show_import_form()
                else:
                    identity, record_id = ref.split("/")
                    if operation == "navigate":
                        self.show_referenced_record(identity, record_id)
                    else:
                        case.annotate(self.case_path, identity, record_id,
                                      "hypothesis" if operation == "finding" else operation, value, self.author.text())
                        self.status("Saved the approved assistant annotation.")
        self.guarded(apply)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case")
    parser.add_argument("--bundle")
    args = parser.parse_args()
    branding.set_app_id()
    app = QApplication([sys.argv[0]])
    app.setStyle("Fusion")
    app.setApplicationName("Windows Traige")
    app.setApplicationVersion(VERSION)
    app.setWindowIcon(QIcon(str(branding.ICON)))
    view = Window(args.case, args.bundle)
    view.show()
    return app.exec()
