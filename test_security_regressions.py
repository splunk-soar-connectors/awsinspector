import re
from pathlib import Path


def test_widget_context_menu_values_use_javascript_escaping() -> None:
    for template in Path(__file__).parent.glob("awsinspector_*.html"):
        content = template.read_text()
        for value in re.findall(r"'value'\s*:\s*'({{.*?}})'", content):
            assert "|escapejs" in value, f"Unescaped context-menu value in {template}: {value}"


def test_paginator_has_hard_page_item_and_token_guards() -> None:
    connector = (Path(__file__).parent / "awsinspector_connector.py").read_text()
    assert "AWSINSPECTOR_MAX_PAGINATION_PAGES" in connector
    assert "AWSINSPECTOR_MAX_PAGINATION_ITEMS" in connector
    assert "next_token in seen_tokens" in connector


def test_all_action_limits_are_normalized_to_integers() -> None:
    connector = (Path(__file__).parent / "awsinspector_connector.py").read_text()
    assert connector.count("limit = int(limit) if limit is not None else None") == 3
