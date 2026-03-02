"""Tool risk classification — pure logic, no I/O, no async."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum


class RiskCategory(IntEnum):
    """Risk categories ordered by severity (higher = more dangerous)."""
    SAFE = 0
    NETWORK = 1
    DATABASE = 2
    FILE = 3
    SHELL = 4


CATEGORY_LABELS = {
    RiskCategory.SAFE: "SAFE",
    RiskCategory.NETWORK: "NETWORK",
    RiskCategory.DATABASE: "DATABASE",
    RiskCategory.FILE: "FILE",
    RiskCategory.SHELL: "SHELL",
}

# Patterns: list of (compiled_regex, weight) per category
# Checked against tool name + description (lowercased)
_SHELL_PATTERNS = [
    (re.compile(r"\b(shell|bash|sh|cmd|subprocess|system|popen|spawn)\b"), 1.0),
    (re.compile(r"\b(exec|execute|run)\b.*\b(command|script|process|program|binary)\b"), 1.0),
    (re.compile(r"\b(command|script|process|program|binary)\b.*\b(exec|execute|run)\b"), 1.0),
    (re.compile(r"\b(terminal|console|process|kill|signal)\b"), 0.8),
    (re.compile(r"\bos\.system\b|os\.popen\b|subprocess\b"), 1.0),
    (re.compile(r"\bexecute_command\b|run_command\b|exec_cmd\b"), 1.0),
]

_FILE_PATTERNS = [
    (re.compile(r"\b(read_file|write_file|create_file|delete_file|remove_file)\b"), 1.0),
    (re.compile(r"\b(file|filesystem|directory|folder|path|mkdir|rmdir|unlink)\b"), 0.8),
    (re.compile(r"\b(save|load|open|close|read|write|append)\b.*\b(file|disk|path)\b"), 0.9),
    (re.compile(r"\b(upload|download)\b"), 0.7),
    (re.compile(r"\b(trace_save|save_trace|write_log|log_file)\b"), 0.6),
]

_DATABASE_PATTERNS = [
    (re.compile(r"\b(sql|query|database|db|table|insert|update|delete|select|drop|alter)\b"), 0.9),
    (re.compile(r"\b(postgres|mysql|sqlite|mongo|redis|dynamo|firestore)\b"), 1.0),
    (re.compile(r"\b(cursor|connection|transaction|commit|rollback)\b"), 0.8),
]

_NETWORK_PATTERNS = [
    (re.compile(r"\b(http|https|request|fetch|api|url|endpoint|webhook)\b"), 0.7),
    (re.compile(r"\b(socket|tcp|udp|connect|listen|bind|port)\b"), 0.9),
    (re.compile(r"\b(send|post|get|put|patch|delete)\b.*\b(request|api|http)\b"), 0.8),
    (re.compile(r"\b(curl|wget|dns|ip|host)\b"), 0.8),
    (re.compile(r"\b(email|smtp|slack|discord|telegram|notify)\b"), 0.6),
]

CATEGORY_PATTERNS = {
    RiskCategory.SHELL: _SHELL_PATTERNS,
    RiskCategory.FILE: _FILE_PATTERNS,
    RiskCategory.DATABASE: _DATABASE_PATTERNS,
    RiskCategory.NETWORK: _NETWORK_PATTERNS,
}


@dataclass
class ToolClassification:
    """Classification result for a single tool."""
    tool_name: str
    category: RiskCategory
    matched_patterns: list[str] = field(default_factory=list)
    confidence: float = 0.0

    @property
    def is_high_risk(self) -> bool:
        return self.category >= RiskCategory.FILE

    @property
    def label(self) -> str:
        return CATEGORY_LABELS[self.category]


def classify_tool(name: str, description: str = "") -> ToolClassification:
    """Classify a single tool by name + description.

    Returns the highest-risk category that matches.
    Priority: SHELL > FILE > DATABASE > NETWORK > SAFE
    """
    text = f"{name} {description}".lower()
    best_category = RiskCategory.SAFE
    best_confidence = 0.0
    all_matched: list[str] = []

    # Check categories in descending risk order
    for category in (RiskCategory.SHELL, RiskCategory.FILE, RiskCategory.DATABASE, RiskCategory.NETWORK):
        patterns = CATEGORY_PATTERNS[category]
        for regex, weight in patterns:
            match = regex.search(text)
            if match:
                all_matched.append(match.group())
                if category > best_category or (category == best_category and weight > best_confidence):
                    best_category = category
                    best_confidence = weight

    return ToolClassification(
        tool_name=name,
        category=best_category,
        matched_patterns=all_matched,
        confidence=best_confidence,
    )


def classify_tools(tools: list[dict]) -> list[ToolClassification]:
    """Classify a list of tools. Each dict needs 'name' and optionally 'description'."""
    return [
        classify_tool(t.get("name", ""), t.get("description", ""))
        for t in tools
    ]
