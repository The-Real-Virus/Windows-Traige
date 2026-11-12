"""Window and profile branding for the native desktop."""

import ctypes
import os
from pathlib import Path

from PySide6.QtCore import QByteArray, QSize, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

ICON = Path(__file__).with_name("assets") / "windows-traige.ico"
PROFILES = {
    "GitHub": "https://github.com/The-Real-Virus",
    "LinkedIn": "https://www.linkedin.com/in/syed-muhammad-shah",
}
# GitHub Octicons mark-github geometry.
GITHUB = ("M8 0a8 8 0 0 0-2.53 15.59c.4.07.55-.17.55-.38v-1.49c-2.22.48-2.69-.94-2.69-.94"
          "-.36-.92-.89-1.16-.89-1.16-.73-.5.05-.49.05-.49.8.06 1.23.82 1.23.82.71 1.22 1.87.87 2.33.66"
          ".07-.52.28-.87.51-1.07-1.77-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.01.08-2.11"
          " 0 0 .67-.22 2.2.82A7.66 7.66 0 0 1 8 3.88c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82"
          ".44 1.1.16 1.91.08 2.11.51.56.82 1.28.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48"
          "v2.19c0 .21.15.46.55.38A8 8 0 0 0 8 0Z")
LINKEDIN = ("M2 0h12a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V2a2 2 0 0 1 2-2Z "
            "M3 6v7h2V6H3Zm1-1a1.15 1.15 0 1 0 0-2.3A1.15 1.15 0 0 0 4 5Zm3 1v7h2V9.2"
            "c0-1 .4-1.6 1.3-1.6 1 0 1.2.7 1.2 1.6V13h2V8.8c0-2-1-3-2.6-3-1 0-1.6.4-2 .9V6H7Z")


def profile_icon(name, color):
    geometry = GITHUB if name == "GitHub" else LINKEDIN
    source = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">'
              f'<path fill="{color}" fill-rule="evenodd" d="{geometry}"/></svg>')
    renderer = QSvgRenderer(QByteArray(source.encode("ascii")))
    pixmap = QPixmap(QSize(36, 36))
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.end()
    return QIcon(pixmap)


def set_app_id():
    if os.name == "nt":
        set_id = ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID
        set_id.argtypes = (ctypes.c_wchar_p,)
        set_id("ViRuS.WindowsTraige")
