"""
CyberScan Report Generator
Génère un rapport HTML + PDF à partir d'un markdown structuré comme suit :

A - Résumé Exécutif
B - Vulnérabilités Prioritaires
C - Vulnérabilités Potentielles à Valider
D - Plan de remédiation
E - Conclusion
## Tableau de synthèse des vulnérabilités
## Annexe - ...

Usage:
    python generate_report.py reports/biat.md
"""

from __future__ import annotations

import html
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional

from jinja2 import Template
from weasyprint import HTML


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_MD = BASE_DIR / "reports" / "biat.md"


# =========================================================
# Utils
# =========================================================

def clean_text(text: str) -> str:
    if not text:
        return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def escape(text: str) -> str:
    return html.escape(text or "")


def normalize_title(title: str) -> str:
    return re.sub(r"\s+", " ", title.strip())

def extract_section(md_text: str, title_regex: str, next_titles: list[str]) -> str:
    start_pattern = re.compile(title_regex, re.IGNORECASE | re.MULTILINE)
    start_match = start_pattern.search(md_text)
    if not start_match:
        return ""

    start = start_match.end()
    end = len(md_text)

    for nxt in next_titles:
        nxt_match = re.compile(nxt, re.IGNORECASE | re.MULTILINE).search(md_text, start)
        if nxt_match:
            end = min(end, nxt_match.start())

    return md_text[start:end].strip()


def split_lines_preserve_blocks(text: str) -> List[str]:
    return [line.rstrip() for line in text.splitlines()]


def find_urls(text: str) -> List[str]:
    return re.findall(r"https?://[^\s<>)]+", text or "")


# =========================================================
# Global metadata
# =========================================================

def extract_risk_label(md_text: str) -> str:
    m = re.search(
        r"Niveau de risque global\s*:\s*\*?\*?([A-ZÉÈÊÀÂÙÛÎÔA-Za-zéèêàâùûîô\-]+)\*?\*?",
        md_text,
        re.IGNORECASE,
    )
    return m.group(1).strip().upper() if m else "NON DÉFINI"


def risk_to_class(label: str) -> str:
    x = (label or "").upper()
    if any(k in x for k in ["FAIBLE", "LOW"]):
        return "low"
    if any(k in x for k in ["MODÉRÉ", "MODERE", "MEDIUM"]):
        return "moderate"
    if any(k in x for k in ["ÉLEVÉ", "ELEVE", "HIGH"]):
        return "high"
    if any(k in x for k in ["CRITIQUE", "CRITICAL"]):
        return "critical"
    return "moderate"


def extract_target(md_text: str) -> str:
    m = re.search(r"Cible\s*:\s*(https?://[^\s()]+)", md_text, re.IGNORECASE)
    return m.group(1).strip() if m else "Cible non spécifiée"


def extract_scan_date(md_text: str) -> str:
    m = re.search(r"Scan du\s*:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})", md_text, re.IGNORECASE)
    if not m:
        return "—"
    yyyy, mm, dd = m.group(1).split("-")
    return f"{dd}/{mm}/{yyyy}"


def extract_counts_from_table(md_text: str) -> dict:
    matches = re.findall(
        r"^\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*$",
        md_text,
        re.MULTILINE,
    )
    if matches:
        critique, eleve, moyen, faible, info = matches[-1]
        return {
            "critique": critique,
            "eleve": eleve,
            "moyen": moyen,
            "faible": faible,
            "info": info,
        }

    return {
        "critique": "0",
        "eleve": "0",
        "moyen": "0",
        "faible": "0",
        "info": "0",
    }

def extract_stat_value(md_text: str, label_regex: str, default: str = "0") -> str:
    m = re.search(
        rf"\*\*?\s*{label_regex}\s*:\s*\*?\*?\s*(\d+)",
        md_text,
        re.IGNORECASE,
    )
    return m.group(1) if m else default


def extract_summary_stats(md_text: str) -> Dict[str, str]:
    return {
        "vulns_total": extract_stat_value(
            md_text,
            r"Vuln[ée]rabilit[ée]s confirm[ée]es retenues dans le rapport",
            "0",
        ),
        "potential_total": extract_stat_value(
            md_text,
            r"Vuln[ée]rabilit[ée]s potentielles [àa] valider",
            "0",
        ),
        "info_total": extract_stat_value(
            md_text,
            r"[ÉE]l[ée]ments informationnels",
            "0",
        ),
        "priority_total": extract_stat_value(
            md_text,
            r"Prioritaires confirm[ée]es \(section B\)",
            "0",
        ),
    }


# =========================================================
# Parsing section B
# =========================================================

FIELD_LABELS = [
    "Description",
    "Référence",
    "Catégorie OWASP",
    "Sévérité",
    "Score CVSS",
    "Recommandation",
    "Vérification",
    "Statut",
    "Délai",
]

ENTRY_START_RE = re.compile(
    r"^(?:\s*(\d+)\.\s+|\s*-\s+)(.+?)\s*$",
    re.MULTILINE,
)


def is_field_line(line: str) -> bool:
    s = line.strip()
    s = re.sub(r"^\*\s*", "", s)
    return any(re.match(rf"^-?\s*{re.escape(lbl)}\s*:", s, re.IGNORECASE) for lbl in FIELD_LABELS) or \
           bool(re.match(r"^\*+\s*Param[èe]tre/Ressource affect", s, re.IGNORECASE))


def is_real_entry_title(title: str) -> bool:
    t = title.strip()
    if not t:
        return False
    if any(t.lower().startswith(lbl.lower() + " :") for lbl in FIELD_LABELS):
        return False
    if re.match(r"^Param[èe]tre/Ressource affect", t, re.IGNORECASE):
        return False
    return True


def split_entries(section_text: str) -> list[str]:
    lines = section_text.splitlines()
    entries = []
    current = []

    def looks_like_plain_title(i: int) -> bool:
        raw = lines[i].rstrip("\n")
        stripped = raw.strip()

        if not stripped:
            return False

        if is_field_line(stripped):
            return False

        if stripped.startswith("http://") or stripped.startswith("https://"):
            return False

        if re.match(r"^[A-E]\s*-\s*", stripped, re.IGNORECASE):
            return False

        if re.match(r"^##\s*", stripped):
            return False

        # cas "Titre nu" suivi d'un champ
        if i + 1 < len(lines):
            next_line = lines[i + 1].strip()
            if is_field_line(next_line):
                return True

        return False

    for i, line in enumerate(lines):
        raw = line.rstrip("\n")
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip(" "))

        start_match = re.match(r"^(?:-\s+|\d+\.\s+)(.+)$", stripped)

        is_new_entry = False
        title_candidate = ""

        # cas 1 : - Titre ou 1. Titre
        if indent == 0 and start_match:
            title_candidate = start_match.group(1).strip()

            if (
                not is_field_line(stripped)
                and is_real_entry_title(title_candidate)
                and not title_candidate.startswith("http://")
                and not title_candidate.startswith("https://")
            ):
                is_new_entry = True

        # cas 2 : Titre nu suivi de "- Description :" ou autre champ
        elif indent == 0 and looks_like_plain_title(i):
            title_candidate = stripped
            is_new_entry = True

        if is_new_entry:
            if current:
                entries.append("\n".join(current).strip())
            current = [raw]
            continue

        if current:
            current.append(raw)

    if current:
        entries.append("\n".join(current).strip())

    return [e for e in entries if e.strip()]

def extract_field(block: str, label: str) -> str:
    pattern = re.compile(
        rf"(?:^|\n)\s*(?:-\s+|\*\s*)?{re.escape(label)}\s*:\s*(.*?)(?=(?:\n\s*(?:-\s+|\*\s*)?(?:{'|'.join(re.escape(x) for x in FIELD_LABELS)}|Param[èe]tre/Ressource affect)[^:\n]*\s*:)|\Z)",
        re.IGNORECASE | re.DOTALL,
    )
    m = pattern.search(block)
    if not m:
        return ""
    return clean_text(m.group(1))


def extract_param(block: str) -> str:
    patterns = [
        r"(?:^|\n)\s*\*\s*Param[èe]tre/Ressource affect[ée]\(e\)\s*:\s*(.+)",
        r"(?:^|\n)\s*-\s*Param[èe]tre/Ressource affect[ée]\(e\)\s*:\s*(.+)",
    ]
    for p in patterns:
        m = re.search(p, block, re.IGNORECASE)
        if m:
            return clean_text(m.group(1))
    return ""


def extract_entry_title(block: str) -> str:
    first = block.splitlines()[0].strip()
    first = re.sub(r"^\d+\.\s+", "", first)
    first = re.sub(r"^-\s+", "", first)
    return normalize_title(first)


def parse_section_b(md_text: str) -> List[Dict[str, str]]:
    sec = extract_section(
        md_text,
        r"^\s*B\s*-\s*Vuln[ée]rabilit[ée]s\s*Prioritaires\s*$",
        [
            r"^\s*C\s*-\s*Vuln[ée]rabilit[ée]s\s*Potentielles",
            r"^\s*D\s*-\s*Plan de rem[ée]diation",
            r"^\s*E\s*-\s*Conclusion",
            r"^\s*##\s*Tableau",
            r"^\s*##\s*Annexe",
        ],
    )
    if not sec:
        return []

    entries = split_entries(sec)
    findings = []

    for block in entries:
        title = extract_entry_title(block)
        refs_raw = extract_field(block, "Référence")
        refs = find_urls(refs_raw)

        finding = {
            "title": title,
            "description": extract_field(block, "Description"),
            "owasp": extract_field(block, "Catégorie OWASP"),
            "severity": extract_field(block, "Sévérité").lower(),
            "cvss": extract_field(block, "Score CVSS"),
            "recommendation": extract_field(block, "Recommandation"),
            "verification": extract_field(block, "Vérification"),
            "parametre": extract_param(block),
            "refs": refs,
        }
        findings.append(finding)

    return findings


# =========================================================
# Parsing section C
# =========================================================

def parse_section_c(md_text: str) -> Dict[str, object]:
    sec = extract_section(
        md_text,
        r"^\s*C\s*-\s*Vuln[ée]rabilit[ée]s\s*Potentielles\s*[àa]\s*Valider\s*$",
        [
            r"^\s*D\s*-\s*Plan de rem[ée]diation",
            r"^\s*E\s*-\s*Conclusion",
            r"^\s*##\s*Tableau",
            r"^\s*##\s*Annexe",
        ],
    )

    if not sec:
        return {"message": "Aucune vulnérabilité potentielle à valider identifiée.", "items": []}

    flat = clean_text(sec).lower()
    if "aucune vulnérabilité potentielle" in flat or "section est vide" in flat:
        return {"message": clean_text(sec), "items": []}

    entries = split_entries(sec)
    items = []

    for block in entries:
        refs_raw = extract_field(block, "Référence")
        items.append({
            "title": extract_entry_title(block),
            "statut": extract_field(block, "Statut"),
            "description": extract_field(block, "Description"),
            "owasp": extract_field(block, "Catégorie OWASP"),
            "severity": extract_field(block, "Sévérité").lower(),
            "delai": extract_field(block, "Délai"),
            "refs": find_urls(refs_raw),
        })

    if not items:
        return {"message": clean_text(sec), "items": []}

    return {"message": "", "items": items}


# =========================================================
# Parsing D / E / A
# =========================================================

def parse_simple_section_to_html(md_text: str, title_regex: str, next_titles: List[str]) -> str:
    sec = extract_section(md_text, title_regex, next_titles)
    if not sec:
        return '<p>Section non disponible.</p>'

    paragraphs = []
    for line in split_lines_preserve_blocks(sec):
        if line.strip():
            paragraphs.append(f"<p>{escape(line.strip())}</p>")
    return "\n".join(paragraphs)


def parse_remediation_items(md_text: str) -> List[Dict[str, str]]:
    sec = extract_section(
        md_text,
        r"^\s*D\s*-\s*Plan de rem[ée]diation\s*$",
        [
            r"^\s*E\s*-\s*Conclusion",
            r"^\s*##\s*Tableau",
            r"^\s*##\s*Annexe",
        ],
    )
    if not sec:
        return []

    items = []
    for line in split_lines_preserve_blocks(sec):
        s = line.strip()
        m = re.match(r"^(\d+)\.\s+(.+)$", s)
        if not m:
            continue

        content = m.group(2).strip()
        delay_match = re.search(r"[—-]\s*D[ée]lai\s*:\s*(.+)$", content, re.IGNORECASE)
        delay = delay_match.group(1).strip() if delay_match else ""

        content_wo_delay = re.sub(r"\s*[—-]\s*D[ée]lai\s*:\s*.+$", "", content, flags=re.IGNORECASE).strip()

        parts = re.split(r"\s*:\s*", content_wo_delay, maxsplit=1)
        title = parts[0].strip()
        action = parts[1].strip() if len(parts) > 1 else ""

        items.append({
            "num": m.group(1),
            "title": title,
            "action": action,
            "delay": delay,
        })

    return items


# =========================================================
# Annexe parser
# =========================================================

def extract_annexe_title_and_table(md_text: str) -> dict:
    annexe_match = re.search(
        r"^\s*##\s*(Annexe.*)$",
        md_text,
        re.IGNORECASE | re.MULTILINE,
    )
    if not annexe_match:
        return {"title": "Annexe", "headers": [], "rows": []}

    title = annexe_match.group(1).strip()
    annexe_text = md_text[annexe_match.end():].strip()

    lines = annexe_text.splitlines()
    table_lines = [ln for ln in lines if ln.strip().startswith("|")]

    if len(table_lines) < 2:
        return {"title": title, "headers": [], "rows": []}

    headers = [c.strip() for c in table_lines[0].strip().strip("|").split("|")]

    rows = []
    for ln in table_lines[2:]:
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        if len(cells) < len(headers):
            cells += [""] * (len(headers) - len(cells))
        elif len(cells) > len(headers):
            cells = cells[:len(headers)]
        rows.append(cells)

    return {"title": title, "headers": headers, "rows": rows}

# =========================================================
# Render helpers
# =========================================================

def sev_badge(sev: str) -> Dict[str, str]:
    s = (sev or "").lower()
    mapping = {
        "critical": {"css": "sev-critical", "label": "Critique"},
        "high": {"css": "sev-high", "label": "Élevé"},
        "medium": {"css": "sev-medium", "label": "Moyen"},
        "low": {"css": "sev-low", "label": "Faible"},
        "info": {"css": "sev-info", "label": "Info"},
    }
    return mapping.get(s, {"css": "sev-info", "label": "Info"})


def render_refs(refs: List[str]) -> str:
    if not refs:
        return ""
    links = []
    for u in refs:
        eu = escape(u)
        links.append(f'<a href="{eu}" target="_blank">{eu}</a>')
    return "<div class='refs-box'><strong>Références :</strong><br>" + "<br>".join(links) + "</div>"


def render_findings(findings: List[Dict[str, str]]) -> str:
    if not findings:
        return "<div class='empty-box'>Aucune vulnérabilité prioritaire identifiée.</div>"

    parts = []
    for idx, f in enumerate(findings, 1):
        sev = sev_badge(f.get("severity", ""))
        rows = []

        if f.get("description"):
            rows.append(
                f"<div class='kv'><div class='k'>Description</div><div class='v'>{escape(f['description'])}</div></div>"
            )
        if f.get("parametre"):
            rows.append(
                f"<div class='kv'><div class='k'>Paramètre/Ressource affecté(e)</div><div class='v'><code>{escape(f['parametre'])}</code></div></div>"
            )
        if f.get("owasp"):
            rows.append(
                f"<div class='kv'><div class='k'>Catégorie OWASP</div><div class='v'>{escape(f['owasp'])}</div></div>"
            )
        if f.get("cvss"):
            rows.append(
                f"<div class='kv'><div class='k'>Score CVSS</div><div class='v'>{escape(f['cvss'])}</div></div>"
            )    
        if f.get("recommendation"):
            rows.append(
                f"<div class='kv'><div class='k'>Recommandation</div><div class='v'>{escape(f['recommendation'])}</div></div>"
            )
        if f.get("verification"):
            rows.append(
                f"<div class='kv'><div class='k'>Vérification</div><div class='v'><pre>{escape(f['verification'])}</pre></div></div>"
            )

        parts.append(
            f"""
            <div class="finding-card">
              <div class="finding-top {sev['css']}">
                <div class="finding-title">#{idx} — {escape(f.get("title", ""))}</div>
                <div class="badge {sev['css']}">{sev['label']}</div>
              </div>
              <div class="finding-body">
                {''.join(rows)}
                {render_refs(f.get('refs', []))}
              </div>
            </div>
            """
        )
    return "\n".join(parts)


def render_potential_section(data: Dict[str, object]) -> str:
    items = data.get("items", [])
    message = data.get("message", "")

    if not items:
        msg = message or "Aucune vulnérabilité potentielle à valider identifiée."
        return f"<div class='empty-box'>{escape(msg)}</div>"

    parts = []
    for idx, f in enumerate(items, 1):
        sev = sev_badge(f.get("severity", ""))
        rows = []

        for key_label, key_name in [
            ("Statut", "statut"),
            ("Description", "description"),
            ("Catégorie OWASP", "owasp"),
            ("Délai", "delai"),
        ]:
            if f.get(key_name):
                rows.append(
                    f"<div class='kv'><div class='k'>{key_label}</div><div class='v'>{escape(f[key_name])}</div></div>"
                )

        parts.append(
            f"""
            <div class="finding-card potential">
              <div class="finding-top {sev['css']}">
                <div class="finding-title">#{idx} — {escape(f.get("title", ""))}</div>
                <div class="badge badge-potential">À valider</div>
              </div>
              <div class="finding-body">
                {''.join(rows)}
                {render_refs(f.get('refs', []))}
              </div>
            </div>
            """
        )

    return "\n".join(parts)


def render_remediation(items: List[Dict[str, str]]) -> str:
    if not items:
        return "<div class='empty-box'>Aucun plan de remédiation disponible.</div>"

    blocks = []
    for item in items:
        delay_html = f"<div class='delay'>{escape(item['delay'])}</div>" if item.get("delay") else ""
        blocks.append(
            f"""
            <div class="rem-item">
              <div class="num">{escape(item['num'])}</div>
              <div class="rem-content">
                <div class="rem-title">{escape(item['title'])}</div>
                <div class="rem-action">{escape(item['action'])}</div>
              </div>
              {delay_html}
            </div>
            """
        )
    return "\n".join(blocks)


# =========================================================
# ✅ ONLY render_synthesis WAS CHANGED — visual bar chart style
# =========================================================
def render_synthesis(counts: Dict[str, str], stats: Dict[str, str], risk_label: str) -> str:
    risk_class = risk_to_class(risk_label)

    sev_colors = {
        "critique": "#dc2626",
        "eleve":    "#ea580c",
        "moyen":    "#d97706",
        "faible":   "#2563eb",
        "info":     "#16a34a",
    }
    sev_labels = {
        "critique": "Critique",
        "eleve":    "Élevé",
        "moyen":    "Moyen",
        "faible":   "Faible",
        "info":     "Info",
    }

    values = {k: int(counts.get(k, 0) or 0) for k in ["critique", "eleve", "moyen", "faible", "info"]}
    max_val = max(values.values()) if any(v > 0 for v in values.values()) else 1

    bar_rows = ""
    for key in ["critique", "eleve", "moyen", "faible", "info"]:
        val = values[key]
        color = sev_colors[key]
        label = sev_labels[key]
        width_pct = max(4, int(val / max_val * 100)) if val > 0 else 4
        if val > 0:
            bar_html = (
                f'<div style="background:{color};width:{width_pct}%;min-width:28px;'
                f'border-radius:4px;padding:2px 8px;color:white;font-weight:bold;'
                f'font-size:10px;text-align:center;display:inline-block;">{val}</div>'
            )
        else:
            bar_html = (
                f'<div style="background:{color};width:28px;border-radius:4px;'
                f'padding:2px 8px;color:white;font-weight:bold;font-size:10px;'
                f'text-align:center;display:inline-block;">0</div>'
            )
        bar_rows += f"""
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
          <div style="min-width:60px;font-size:9.5px;color:#475569;text-align:right;">{label}:</div>
          {bar_html}
        </div>"""

    risk_pill_styles = {
        "low":      "background:#2563eb;color:white;",
        "moderate": "background:#d97706;color:white;",
        "high":     "background:#ea580c;color:white;",
        "critical": "background:#dc2626;color:white;",
    }
    risk_pill_css = risk_pill_styles.get(risk_class, "background:#2563eb;color:white;")

    return f"""
    <div class="synthesis-block">
      <h2>Tableau de synthèse des vulnérabilités</h2>
      <div style="display:flex;gap:32px;align-items:flex-start;padding:14px 0 6px;">

        <div style="min-width:140px;">
          <div style="font-size:9.5px;font-weight:bold;color:#2563eb;margin-bottom:6px;">Niveau de risque global :</div>
          <div style="{risk_pill_css}border-radius:6px;padding:6px 18px;font-size:12px;font-weight:bold;text-align:center;display:inline-block;">
            {escape(risk_label.capitalize())}
          </div>
        </div>

        <div style="width:1px;background:#dbe3ee;align-self:stretch;"></div>

        <div style="flex:1;">
          <div style="font-size:9.5px;font-weight:bold;color:#2563eb;margin-bottom:8px;">Répartition des niveaux de sévérité :</div>
          {bar_rows}
        </div>

      </div>

      <div class="note-box" style="margin-top:12px;">
       <strong>Note méthodologique :</strong> Les vulnérabilités potentielles à valider et les éléments informationnels sont comptabilisés séparément.
      </div>

      <div class="stat-row">
        <div class="pill confirmed">
            <span>Vulnérabilités confirmées retenues</span>
            <strong>{escape(stats['vulns_total'])}</strong>
        </div>
        <div class="pill potential">
            <span>Vulnérabilités potentielles à valider</span>
            <strong>{escape(stats['potential_total'])}</strong>
        </div>
        <div class="pill info">
            <span>Éléments informationnels</span>
            <strong>{escape(stats['info_total'])}</strong>
        </div>
        <div class="pill accent">
            <span>Prioritaires confirmées (section B)</span>
            <strong>{escape(stats['priority_total'])}</strong>
        </div>
        </div>

      <div class="small-note">ℹ️ Les chiffres ci-dessus sont calculés après déduplication globale.</div>
    </div>
    """


def render_annexe(annexe: Dict[str, object]) -> str:
    headers = annexe.get("headers", [])
    rows = annexe.get("rows", [])
    title = annexe.get("title", "Annexe")

    if not headers or not rows:
        return f"<h2>{escape(title)}</h2><div class='empty-box'>Annexe non disponible.</div>"

    ths = "".join(f"<th>{escape(h)}</th>" for h in headers)
    trs = []

    for row in rows:
        tds = []
        for cell in row:
            cell_escaped = escape(cell)
            lower = cell.strip().lower()
            cls = ""
            if lower == "critical":
                cls = "class='sev-critical-text'"
            elif lower == "high":
                cls = "class='sev-high-text'"
            elif lower == "medium":
                cls = "class='sev-medium-text'"
            elif lower == "low":
                cls = "class='sev-low-text'"
            elif lower == "info":
                cls = "class='sev-info-text'"
            tds.append(f"<td {cls}>{cell_escaped}</td>")
        trs.append("<tr>" + "".join(tds) + "</tr>")

    return f"""
    <div class="page-break"></div>
    <h2>{escape(title)}</h2>
    <table class="annexe-table">
      <thead><tr>{ths}</tr></thead>
      <tbody>
        {''.join(trs)}
      </tbody>
    </table>
    """


# =========================================================
# HTML template
# =========================================================

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8" />
  <title>CyberScan Report</title>
  <style>
    @page { size: A4; margin: 10mm; }

    :root{
      --primary:#173a5e;
      --accent:#2563eb;
      --border:#dbe3ee;
      --bg:#f8fafc;
      --text:#1f2937;
      --muted:#64748b;
      --success:#16a34a;
      --warning:#d97706;
      --danger:#dc2626;
      --info:#0891b2;
    }

    *{ box-sizing:border-box; }
    body{
      font-family: Arial, Helvetica, sans-serif;
      color:var(--text);
      font-size:10.5px;
      line-height:1.55;
      margin:0;
      padding:0;
    }

    .cover{
      page-break-after:always;
      background:linear-gradient(145deg,#0f2540 0%, #173a5e 55%, #1e4d8c 100%);
      color:white;
      border-radius:16px;
      padding:18mm;
      min-height:270mm;
      position:relative;
      overflow:hidden;
    }

    .cover .tag{
      display:inline-block;
      padding:5px 12px;
      border:1px solid rgba(255,255,255,.2);
      border-radius:20px;
      font-size:9px;
      letter-spacing:1px;
      text-transform:uppercase;
      opacity:.9;
    }

    .cover h1{
      margin:18px 0 6px;
      font-size:30px;
      line-height:1.15;
    }

    .cover .subtitle{
      opacity:.8;
      font-size:13px;
      margin-bottom:24px;
    }

    .risk-box{
      display:inline-block;
      padding:10px 14px;
      border-radius:10px;
      background:rgba(255,255,255,.12);
      border:1px solid rgba(255,255,255,.2);
      margin-bottom:16px;
    }

    .stats-grid{
      display:grid;
      grid-template-columns:repeat(5,1fr);
      gap:10px;
      margin-top:18px;
    }

    .stat{
      background:rgba(255,255,255,.08);
      border:1px solid rgba(255,255,255,.14);
      border-radius:10px;
      padding:10px;
      text-align:center;
    }

    .stat strong{
      display:block;
      font-size:20px;
      color:white;
    }

    .stat span{
      font-size:8.5px;
      text-transform:uppercase;
      opacity:.7;
    }

    .content{
      padding:0;
    }

    .topbar{
      display:flex;
      justify-content:space-between;
      align-items:flex-start;
      border-bottom:2px solid var(--primary);
      padding-bottom:8px;
      margin-bottom:14px;
    }

    .topbar .brand{
      font-size:15px;
      font-weight:bold;
      color:var(--primary);
    }

    .topbar .meta{
      font-size:9px;
      color:var(--muted);
      text-align:right;
    }

    h2{
      color:var(--primary);
      border-left:4px solid var(--accent);
      padding-left:10px;
      margin:20px 0 10px;
      font-size:13px;
      page-break-after:avoid;
    }

    p{ margin:0 0 7px; }

    .box{
      background:var(--bg);
      border:1px solid var(--border);
      border-radius:10px;
      padding:12px 14px;
    }

    .finding-card{
      border:1px solid var(--border);
      border-radius:10px;
      overflow:hidden;
      margin:12px 0 16px;
      page-break-inside:avoid;
      background:white;
    }

    .finding-card.potential{
      border-style:dashed;
    }

    .finding-top{
      display:flex;
      justify-content:space-between;
      align-items:center;
      gap:12px;
      padding:10px 14px;
      background:#f8fafc;
      border-left:6px solid var(--accent);
    }

    .finding-top.sev-critical{ border-left-color:var(--danger); }
    .finding-top.sev-high{ border-left-color:#ea580c; }
    .finding-top.sev-medium{ border-left-color:var(--warning); }
    .finding-top.sev-low{ border-left-color:var(--success); }
    .finding-top.sev-info{ border-left-color:var(--info); }

    .finding-title{
      font-weight:bold;
      color:var(--primary);
      font-size:11.5px;
    }

    .badge{
      border-radius:999px;
      padding:4px 8px;
      font-size:8.5px;
      font-weight:bold;
      text-transform:uppercase;
      white-space:nowrap;
      border:1px solid transparent;
    }

    .badge.sev-critical{ background:#fef2f2; color:var(--danger); border-color:#fecaca; }
    .badge.sev-high{ background:#fff7ed; color:#ea580c; border-color:#fed7aa; }
    .badge.sev-medium{ background:#fffbeb; color:var(--warning); border-color:#fde68a; }
    .badge.sev-low{ background:#f0fdf4; color:var(--success); border-color:#bbf7d0; }
    .badge.sev-info{ background:#ecfeff; color:var(--info); border-color:#a5f3fc; }
    .badge-potential{ background:#fff7ed; color:#ea580c; border:1px solid #fed7aa; }

    .finding-body{
      padding:12px 14px;
    }

    .kv{
      display:flex;
      gap:10px;
      margin-bottom:8px;
      align-items:flex-start;
    }

    .k{
      min-width:130px;
      font-weight:bold;
      color:var(--text);
    }

    .v{
      flex:1;
      color:#475569;
    }

    .refs-box{
      margin-top:10px;
      padding-top:8px;
      border-top:1px solid var(--border);
      font-size:9.2px;
      color:var(--muted);
    }

    .refs-box a{
      color:var(--accent);
      text-decoration:none;
      word-break:break-all;
    }

    pre, code{
      font-family:"Courier New", monospace;
    }

    pre{
      white-space:pre-wrap;
      overflow-wrap:anywhere;
      background:#0f172a;
      color:#e2e8f0;
      padding:8px 10px;
      border-radius:6px;
      margin:0;
      font-size:9px;
    }

    code{
      background:#eef2f7;
      padding:1px 4px;
      border-radius:4px;
    }

    .empty-box{
      background:#f8fafc;
      border:1px dashed var(--border);
      border-radius:10px;
      padding:12px 14px;
      color:var(--muted);
      font-style:italic;
    }

    .rem-item{
      position:relative;
      border:1px solid var(--border);
      border-radius:10px;
      padding:10px 80px 10px 46px;
      margin-bottom:10px;
      page-break-inside:avoid;
      background:white;
    }

    .rem-item .num{
      position:absolute;
      top:10px;
      left:12px;
      width:24px;
      height:24px;
      border-radius:50%;
      background:var(--primary);
      color:white;
      display:flex;
      align-items:center;
      justify-content:center;
      font-size:10px;
      font-weight:bold;
    }

    .rem-title{
      font-weight:bold;
      color:var(--primary);
      margin-bottom:4px;
    }

    .rem-action{
      color:#475569;
    }

    .delay{
      position:absolute;
      right:12px;
      top:10px;
      background:#eff6ff;
      color:var(--accent);
      border:1px solid #bfdbfe;
      border-radius:999px;
      padding:3px 8px;
      font-size:8.5px;
      font-weight:bold;
    }

    .note-box{
      background:#fffbeb;
      border:1px solid #fde68a;
      border-left:4px solid var(--warning);
      border-radius:8px;
      padding:10px 12px;
      color:#92400e;
      margin:10px 0 14px;
    }

    .summary-table, .annexe-table{
      width:100%;
      border-collapse:collapse;
      table-layout:fixed;
      margin:12px 0 14px;
      font-size:9px;
    }

    .summary-table th, .annexe-table th{
      background:var(--primary);
      color:white;
      border:1px solid var(--primary);
      padding:8px;
      text-align:center;
      font-size:8.5px;
    }

    .summary-table td, .annexe-table td{
      border:1px solid var(--border);
      padding:7px 8px;
      vertical-align:top;
      overflow-wrap:anywhere;
      word-wrap:break-word;
    }

    .summary-table td{
      text-align:center;
      font-weight:bold;
      font-size:12px;
    }

    .stat-row{
        display:grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap:10px;
        margin-top:14px;
        width:100%;
        }

   .pill{
        min-width:0;
        width:100%;
        background:linear-gradient(to bottom, #ffffff, #f8fafc);
        border:1px solid #dbe3ee;
        border-radius:14px;
        padding:12px 10px;
        text-align:center;
        box-shadow:0 2px 8px rgba(15, 23, 42, 0.04);
        position:relative;
        }

.pill::before{
  content:"";
  position:absolute;
  top:0;
  left:0;
  right:0;
  height:4px;
  border-radius:14px 14px 0 0;
  background:#cbd5e1;
}

.pill span{
  display:block;
  font-size:8px;
  color:#64748b;
  text-transform:uppercase;
  letter-spacing:0.2px;
  line-height:1.35;
  margin-bottom:8px;
}

.pill strong{
  display:block;
  color:#173a5e;
  font-size:20px;
  font-weight:700;
  line-height:1;
}

/* Couleurs par type */
.pill.confirmed::before{
  background:#2563eb;
}

.pill.potential::before{
  background:#f59e0b;
}

.pill.info::before{
  background:#16a34a;
}

.pill.accent{
  background:#f8fbff;
  border-color:#bfdbfe;
}

.pill.accent::before{
  background:#1d4ed8;
}
.pill:hover{
  transform:translateY(-2px);
  box-shadow:0 6px 16px rgba(15,23,42,0.08);
}

    .small-note{
      margin-top:8px;
      font-size:9px;
      color:var(--muted);
      font-style:italic;
    }

    .sev-critical-text{ color:var(--danger); font-weight:bold; }
    .sev-high-text{ color:#ea580c; font-weight:bold; }
    .sev-medium-text{ color:var(--warning); font-weight:bold; }
    .sev-low-text{ color:var(--success); font-weight:bold; }
    .sev-info-text{ color:var(--info); font-weight:bold; }

    .page-break{ page-break-before:always; }

    .footer{
      margin-top:18px;
      padding-top:8px;
      border-top:1px solid var(--border);
      display:flex;
      justify-content:space-between;
      font-size:8.5px;
      color:var(--muted);
    }
  </style>
</head>
<body>

  <div class="content">
    <div class="topbar">
      <div>
        <div class="brand">CyberScan Report</div>
        <div style="font-size:9px; color:#64748b;">Analyse automatisée des vulnérabilités web</div>
      </div>
      <div class="meta">
        <div><strong>Cible :</strong> {{ target_url }}</div>
        <div><strong>Date :</strong> {{ scan_date }}</div>
      </div>
    </div>
     {{ synthesis_html | safe }}
     
    <h2>A - Résumé Exécutif</h2>
    <div class="box">{{ executive_summary | safe }}</div>

    <h2>B - Vulnérabilités Prioritaires</h2>
    {{ findings_html | safe }}

    <h2>C - Vulnérabilités Potentielles à Valider</h2>
    {{ potential_html | safe }}

    <h2>D - Plan de remédiation</h2>
    {{ remediation_html | safe }}

    <h2>E - Conclusion</h2>
    <div class="box">{{ conclusion_html | safe }}</div>

    {{ annexe_html | safe }}

    <div class="footer">
      <span>Généré automatiquement par CyberScan</span>
      <span>Rapport confidentiel — Ne pas distribuer</span>
      <span>{{ scan_date }}</span>
    </div>
  </div>
</body>
</html>
"""


# =========================================================
# Main
# =========================================================
def generate_pdf_from_markdown(report_path: str | Path) -> tuple[Path, Path]:
    report_path = Path(report_path)
    if not report_path.exists():
        raise FileNotFoundError(f"Fichier introuvable : {report_path}")

    md_text = report_path.read_text(encoding="utf-8")
    md_text = md_text.replace("\r\n", "\n").replace("\r", "\n")

    risk_label = extract_risk_label(md_text)
    risk_class = risk_to_class(risk_label)
    target_url = extract_target(md_text)
    scan_date = extract_scan_date(md_text)
    counts = extract_counts_from_table(md_text)
    stats = extract_summary_stats(md_text)

    findings = parse_section_b(md_text)
    potential = parse_section_c(md_text)
    remediation_items = parse_remediation_items(md_text)
    annexe = extract_annexe_title_and_table(md_text)

    executive_summary = parse_simple_section_to_html(
        md_text,
        r"^\s*A\s*-\s*R[ée]sum[ée]\s*Ex[ée]cutif\s*$",
        [
            r"^\s*B\s*-\s*Vuln[ée]rabilit[ée]s\s*Prioritaires",
            r"^\s*C\s*-\s*Vuln[ée]rabilit[ée]s\s*Potentielles",
        ],
    )

    conclusion_html = parse_simple_section_to_html(
        md_text,
        r"^\s*E\s*-\s*Conclusion\s*$",
        [
            r"^\s*##\s*Tableau",
            r"^\s*##\s*Annexe",
        ],
    )

    findings_html = render_findings(findings)
    potential_html = render_potential_section(potential)
    remediation_html = render_remediation(remediation_items)
    synthesis_html = render_synthesis(counts, stats, risk_label)
    annexe_html = render_annexe(annexe)

    template = Template(HTML_TEMPLATE)
    final_html = template.render(
        risk_label=risk_label,
        risk_class=risk_class,
        target_url=target_url,
        scan_date=scan_date,
        critique=counts["critique"],
        eleve=counts["eleve"],
        moyen=counts["moyen"],
        faible=counts["faible"],
        info=counts["info"],
        executive_summary=executive_summary,
        findings_html=findings_html,
        potential_html=potential_html,
        remediation_html=remediation_html,
        conclusion_html=conclusion_html,
        synthesis_html=synthesis_html,
        annexe_html=annexe_html,
    )

    output_html = report_path.with_name(report_path.stem + "_rendered.html")
    output_pdf = report_path.with_name(report_path.stem + "_rapport.pdf")

    output_html.write_text(final_html, encoding="utf-8")
    HTML(string=final_html, base_url=str(report_path.parent)).write_pdf(str(output_pdf))

    return output_html, output_pdf


def main() -> None:
    report_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_MD
    if not report_path.exists():
        print(f"❌ Fichier introuvable : {report_path}")
        sys.exit(1)

    print(f"📄 Lecture du rapport : {report_path}")
    output_html, output_pdf = generate_pdf_from_markdown(report_path)
    print(f"🌐 HTML généré : {output_html}")
    print(f"✅ PDF généré : {output_pdf}")


if __name__ == "__main__":
    main()