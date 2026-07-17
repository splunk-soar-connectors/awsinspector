# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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
