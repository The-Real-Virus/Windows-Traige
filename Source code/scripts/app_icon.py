"""Create the checked-in Windows Traige icon using the bundled Pillow runtime."""

from pathlib import Path
from PIL import Image, ImageDraw

root = Path(__file__).resolve().parents[1] / "src" / "windows_traige" / "assets"
root.mkdir(exist_ok=True)
image = Image.new("RGBA", (512, 512))
draw = ImageDraw.Draw(image)
draw.rounded_rectangle((36, 36, 476, 476), 101, fill="#11243b")
draw.rounded_rectangle((44, 44, 468, 468), 95, outline="#395571", width=5)
shield = [(256, 94), (382, 140), (382, 251), (368, 311), (331, 357), (256, 412),
          (181, 357), (144, 311), (130, 251), (130, 140)]
draw.polygon(shield, fill="#1c3d5d")
draw.line(shield + [shield[0]], fill="#79d5f0", width=21, joint="curve")
draw.line((299, 284, 345, 329), fill="#effaff", width=24)
draw.ellipse((174, 162, 309, 297), outline="#effaff", width=20)
draw.line((204, 241, 225, 241, 235, 216, 247, 260, 260, 233, 279, 233), fill="#76d9b9", width=10, joint="curve")
icon = image.resize((256, 256), Image.Resampling.LANCZOS)
icon.save(root / "windows-traige.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
