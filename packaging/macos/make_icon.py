"""Draws the app icon (a magnifier over a database cylinder) at every macOS size into an .iconset folder. usage: make_icon.py <out.iconset>"""
import sys
from pathlib import Path

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QBrush, QColor, QGuiApplication, QImage, QLinearGradient, QPainter, QPen

app = QGuiApplication([])


def draw(px: int) -> QImage:
    img = QImage(px, px, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    s = px / 1024
    g = QLinearGradient(0, 0, 0, px)
    g.setColorAt(0, QColor("#1f6f5c"))
    g.setColorAt(1, QColor("#0d3b44"))
    p.setBrush(QBrush(g))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(QRectF(60 * s, 60 * s, 904 * s, 904 * s), 200 * s, 200 * s)
    p.setBrush(QColor("#e8f3ef"))                      # database cylinder
    for i, y in enumerate((300, 430, 560)):
        p.drawRoundedRect(QRectF(250 * s, y * s, 400 * s, 110 * s), 40 * s, 40 * s)
        p.setBrush(QColor("#bcd9d0") if i == 0 else QColor("#e8f3ef"))
    p.setBrush(Qt.BrushStyle.NoBrush)                  # magnifier
    p.setPen(QPen(QColor("#ffcf5c"), 56 * s, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    p.drawEllipse(QPointF(600 * s, 560 * s), 190 * s, 190 * s)
    p.drawLine(QPointF(735 * s, 695 * s), QPointF(850 * s, 810 * s))
    p.end()
    return img


out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
for base in (16, 32, 128, 256, 512):
    draw(base).save(str(out / f"icon_{base}x{base}.png"))
    draw(base * 2).save(str(out / f"icon_{base}x{base}@2x.png"))
