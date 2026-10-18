"""Testes estáticos do portal visual. Não requer Mininet, rede ou root."""
from html.parser import HTMLParser
from pathlib import Path
import re
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "docs" / "index.html"


class AssetParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.images = []

    def handle_starttag(self, tag, attrs):
        data = dict(attrs)
        if "id" in data:
            self.ids.append(data["id"])
        if tag == "img":
            self.images.append(data.get("src", ""))


def test_portal_assets_and_unique_ids():
    text = PAGE.read_text(encoding="utf-8")
    parser = AssetParser()
    parser.feed(text)
    assert len(parser.ids) == len(set(parser.ids)), "IDs duplicados no HTML"
    assert parser.images, "Portal sem imagens descritivas"
    for path in parser.images:
        assert not path.startswith(("http://", "https://")), "Evitar imagens externas"
        assert (PAGE.parent / path).is_file(), f"Imagem ausente: {path}"
    for svg in [
        ROOT / "docs" / "assets" / "mininet-hero.svg",
        ROOT / "docs" / "assets" / "mininet-banner.svg",
    ]:
        tree = ET.parse(svg)
        assert tree.getroot().tag.endswith("svg")
    assert "prefers-reduced-motion" in text
    assert "aria-pressed" in text
    assert "NÃO LIVE" in text or "NÃO AO VIVO" in text


def test_case_cards_match_repo_files():
    html = PAGE.read_text(encoding="utf-8")
    declared = re.findall(r'\["\d{2}","(?:ot|it)","(case\d{2}_[a-z0-9_]+)"', html)
    present = [p.stem for p in (ROOT / "cases").glob("case??_*.py")]
    assert len(declared) == 12
    assert set(declared) == set(present), "O portal e a pasta cases divergiram"
    assert len(set(declared)) == len(declared)
    assert 'id="map-it"' in html and 'id="map-ot"' in html
    assert 'textContent=' in html, "Preenchimento de detalhes deve ser seguro"


def test_readme_visual_files():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for rel in [
        "docs/index.html",
        "docs/assets/mininet-hero.svg",
        "docs/assets/mininet-banner.svg",
        "docs/IDENTIDADE-VISUAL.md",
    ]:
        assert rel in readme
        assert (ROOT / rel).is_file()
