#!/usr/bin/env python3
import json
import os
import sys
from typing import Dict, Any


def to_enum_name(name: str) -> str:
    """
    Convert a Font Awesome icon name like 'circle-arrow-left'
    to a Java enum constant name 'CIRCLE_ARROW_LEFT'.
    """
    enum_name = name.upper().replace("-", "_")
    # If it starts with a digit, prefix with underscore
    if enum_name and enum_name[0].isdigit():
        enum_name = "_" + enum_name
    # Replace any remaining illegal chars with underscore
    result = []
    for ch in enum_name:
        if ("A" <= ch <= "Z") or ("0" <= ch <= "9") or ch == "_":
            result.append(ch)
        else:
            result.append("_")
    return "".join(result)


def load_icons_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main(argv: list[str]) -> int:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    icons_path = os.path.abspath(os.path.join(
        script_dir,
        "icons.json",
    ))

    if not os.path.isfile(icons_path):
        print(f"icons.json not found at: {icons_path}", file=sys.stderr)
        return 1

    data = load_icons_json(icons_path)

    # data is expected to be a dict: { icon_name: { unicode: 'f023', styles: [...], ... }, ... }
    entries = []
    for name, meta in data.items():
        if not isinstance(meta, dict):
            continue

        # Only include icons that have a 'styles' array containing 'solid'
        styles = meta.get("styles")
        if not isinstance(styles, list):
            continue
        # Normalize style names to lowercase strings and check for 'solid'
        if not any(str(style).lower() == "solid" for style in styles):
            continue

        unicode_val = meta.get("unicode")
        if not unicode_val:
            continue

        enum_name = to_enum_name(name)
        entries.append((enum_name, unicode_val))

    # Sort for stable, readable output
    entries.sort(key=lambda x: x[0])

    # Print Java enum constants
    for enum_name, unicode_val in entries:
        # Ensure lowercase hex and pad to 4 characters if only 2 characters long
        hex_code = unicode_val.lower()
        if len(hex_code) == 2:
            hex_code = "00" + hex_code
        print(f"    {enum_name}('\\u{hex_code}'),")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
