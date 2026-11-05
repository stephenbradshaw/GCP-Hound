#!/usr/bin/env python3
"""Generate the README graph-schema section from the extension schema.

Reads gcp-extension-schema.json and bloodhound/opengraph_kinds.py, and
rewrites the README section between the GENERATED GRAPH SCHEMA markers.
Run after adding/changing node or relationship kinds so the docs cannot
drift from the schema.
"""
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
README = REPO_ROOT / "README.md"
SCHEMA = REPO_ROOT / "gcp-extension-schema.json"

BEGIN = "<!-- BEGIN GENERATED GRAPH SCHEMA -->"
END = "<!-- END GENERATED GRAPH SCHEMA -->"


def build_section(schema, traversable):
    node_kinds = schema.get("node_kinds", [])
    rel_kinds = schema.get("relationship_kinds", [])

    lines = []
    lines.append(f"GCP-Hound currently registers **{len(node_kinds)} node kinds** "
                 f"and **{len(rel_kinds)} relationship kinds** in the BloodHound "
                 f"OpenGraph extension schema:")
    lines.append("")
    lines.append("### Node kinds")
    lines.append("")
    lines.append("| Node kind | Icon |")
    lines.append("|-----------|------|")
    for kind in node_kinds:
        lines.append(f"| `{kind['name']}` | {kind.get('icon', '')} |")
    lines.append("")
    lines.append("### Relationship kinds")
    lines.append("")
    lines.append("Edges marked **traversable** participate in BloodHound CE pathfinding; "
                 "the rest are inventory/context edges.")
    lines.append("")
    lines.append("| Relationship kind | Traversable |")
    lines.append("|--------------------|-------------|")
    for kind in rel_kinds:
        trav = "yes" if kind["name"] in traversable else ""
        lines.append(f"| `{kind['name']}` | {trav} |")
    lines.append("")
    return "\n".join(lines)


def main():
    schema = json.loads(SCHEMA.read_text())
    import sys
    sys.path.insert(0, str(REPO_ROOT))
    from bloodhound.opengraph_kinds import TRAVERSABLE_EDGE_KINDS

    section = build_section(schema, TRAVERSABLE_EDGE_KINDS)
    text = README.read_text()
    if BEGIN in text and END in text:
        pre = text[:text.index(BEGIN) + len(BEGIN)]
        post = text[text.index(END):]
        README.write_text(pre + "\n" + section + post)
        print(f"Updated generated section between markers in {README.name}")
        return

    # First run: replace the legacy "Enumerated Resources & Relationships"
    # tables wholesale with the generated section.
    header = "## Enumerated Resources & Relationships"
    if header in text:
        start = text.index(header)
        # Find the next section header after the legacy tables
        rest = text[start + len(header):]
        next_header = None
        for marker in ("\n## ",):
            idx = rest.find(marker)
            if idx != -1 and (next_header is None or idx < next_header):
                next_header = idx
        legacy = text[start:start + len(header) + (next_header or 0)]
        new_section = (header + "\n\n" + BEGIN + "\n" + section + END + "\n\n")
        README.write_text(text[:start] + new_section + text[start + len(header) + (next_header or 0):])
        print("Replaced legacy schema tables with generated section")
        return

    print("No insertion point found; add '## Enumerated Resources & Relationships' "
          "or the generated markers manually.")


if __name__ == "__main__":
    main()