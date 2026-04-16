import asyncio
import re
import sys
from pathlib import Path

import markdown
from playwright.async_api import async_playwright


TEMPLATE_PATH = Path("template_report.html")


def clean_markdown(md: str) -> str:
    # Supprimer les fragments parasites exacts
    bad_patterns = [
        r"ERROR\s*fo",
        r"Invalid\s*do",
        r"ERROR",
        r"Invalid do",
    ]

    for pattern in bad_patterns:
        md = re.sub(pattern, "", md, flags=re.IGNORECASE)

    # Supprimer les lignes contenant ces fragments
    md = re.sub(r"^.*ERROR.*$", "", md, flags=re.MULTILINE | re.IGNORECASE)
    md = re.sub(r"^.*Invalid.*do.*$", "", md, flags=re.MULTILINE | re.IGNORECASE)

    # Nettoyage caractères parasites
    md = md.replace("\x00", "")
    md = md.replace("\ufeff", "")
    md = md.replace("\ufffd", "")

    # Réduire les multiples lignes vides
    md = re.sub(r"\n{3,}", "\n\n", md)

    return md.strip()

def build_html(md_path: Path) -> str:
    if not md_path.exists():
        raise FileNotFoundError(f"Markdown introuvable : {md_path}")

    if not TEMPLATE_PATH.exists():
        raise FileNotFoundError(f"Template introuvable : {TEMPLATE_PATH}")

    md = md_path.read_text(encoding="utf-8")
    md = clean_markdown(md)

    template = TEMPLATE_PATH.read_text(encoding="utf-8")

    html_content = markdown.markdown(
        md,
        extensions=[
            "tables",
            "fenced_code",
            "nl2br",
            "sane_lists",
        ],
    )

    if "{{CONTENT}}" not in template:
        raise ValueError("Le template doit contenir {{CONTENT}}")

    return template.replace("{{CONTENT}}", html_content)


async def generate_pdf(html_content: str, output_path: Path) -> None:
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()

        await page.set_content(html_content)
        await page.wait_for_timeout(1200)

        await page.pdf(
            path=str(output_path),
            format="A4",
            print_background=True,
            display_header_footer=True,
            header_template="""
                <div style="width:100%; font-size:9px; color:#666; text-align:center;"></div>
            """,
            footer_template="""
                <div style="width:100%; font-size:9px; color:#666; text-align:center; padding:0 10px;">
                    Page <span class="pageNumber"></span> / <span class="totalPages"></span>
                </div>
            """,
            margin={
                "top": "18mm",
                "right": "14mm",
                "bottom": "18mm",
                "left": "14mm",
            },
        )

        await browser.close()


async def main():
    if len(sys.argv) < 2:
        print("Usage: python pdf_export.py <markdown_file>")
        sys.exit(1)

    md_path = Path(sys.argv[1])
    pdf_path = md_path.with_suffix(".pdf")

    try:
        html = build_html(md_path)
        await generate_pdf(html, pdf_path)
        print(f"✅ PDF généré : {pdf_path}")
    except Exception as e:
        print(f"❌ Erreur : {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())