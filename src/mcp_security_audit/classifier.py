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
    (re.compile(r"\b(terminal|console)\b"), 0.8),
    (re.compile(r"\b(kill|signal)\b.*\b(process|pid|proc)\b"), 0.8),
    (re.compile(r"\b(child|system|spawn|fork)\b.*\bprocess\b"), 0.8),
    (re.compile(r"\bos\.system\b|os\.popen\b|subprocess\b"), 1.0),
    (re.compile(r"\bexecute_command\b|run_command\b|exec_cmd\b"), 1.0),
]

_FILE_PATTERNS = [
    # Explicit file operation tool names
    (re.compile(r"\b(read_file|write_file|create_file|delete_file|remove_file)\b"), 1.0),
    (re.compile(r"\b(filesystem|mkdir|rmdir|unlink)\b"), 0.9),
    # File operations with action context (not just mentioning "file")
    (re.compile(r"\b(read|write|create|delete|remove|modify|edit)\b.*\b(file|files)\b"), 0.9),
    (re.compile(r"\b(file|files)\b.*\b(read|write|create|delete|remove|modify|edit)\b"), 0.9),
    (re.compile(r"\b(save|load|open|close|append)\b.*\b(file|disk|path)\b"), 0.9),
    (re.compile(r"\b(save|write)\b.*\b(to disk|to file)\b"), 0.9),
    (re.compile(r"\b(upload|download)\b.*\b(file|files)\b"), 0.8),
    (re.compile(r"\b(trace_save|save_trace|write_log|log_file)\b"), 0.6),
]

_DATABASE_PATTERNS = [
    # SQL-specific terms (not ambiguous)
    (re.compile(r"\b(sql|query|database|db)\b"), 0.9),
    (re.compile(r"\b(insert|select|drop|alter)\b.*\b(table|row|column|record|into)\b"), 0.9),
    # Specific database systems
    (re.compile(r"\b(postgres|mysql|sqlite|mongo|redis|dynamo|firestore|supabase)\b"), 1.0),
    # Only match "commit/rollback/transaction" with database context
    (re.compile(r"\b(transaction|rollback)\b"), 0.8),
    (re.compile(r"\b(commit|cursor|connection)\b.*\b(database|db|sql|transaction)\b"), 0.8),
]

_NETWORK_PATTERNS = [
    (re.compile(r"\b(http|https|url|endpoint|webhook)\b"), 0.7),
    (re.compile(r"\b(socket|tcp|udp|listen|bind)\b"), 0.9),
    (re.compile(r"\b(send|post|get|put|patch)\b.*\b(request|api|http)\b"), 0.8),
    (re.compile(r"\b(curl|wget|dns)\b"), 0.8),
    (re.compile(r"\b(email|smtp|slack|discord|telegram)\b"), 0.6),
    (re.compile(r"\bfetch\b.*\b(url|http|web|page|content)\b"), 0.7),
    (re.compile(r"\b(api|request)\b.*\b(call|send|make)\b"), 0.7),
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

    Uses a scoring approach: each category accumulates a score from its
    pattern matches. The category with the highest total score wins,
    but only if it exceeds a minimum threshold.
    """
    text = f"{name} {description}".lower()

    category_scores: dict[RiskCategory, float] = {}
    category_matches: dict[RiskCategory, list[str]] = {}

    for category in (RiskCategory.SHELL, RiskCategory.FILE, RiskCategory.DATABASE, RiskCategory.NETWORK):
        score = 0.0
        matches: list[str] = []
        for regex, weight in CATEGORY_PATTERNS[category]:
            match = regex.search(text)
            if match:
                matched_text = match.group()
                # Truncate long matches to keep output clean
                if len(matched_text) > 40:
                    matched_text = matched_text[:40] + "..."
                matches.append(matched_text)
                score += weight
        if matches:
            category_scores[category] = score
            category_matches[category] = matches

    if not category_scores:
        return ToolClassification(tool_name=name, category=RiskCategory.SAFE)

    # Pick the category with the highest score;
    # on ties, higher risk category wins
    best_category = max(
        category_scores,
        key=lambda c: (category_scores[c], c.value),
    )
    all_matched = []
    for matches in category_matches.values():
        all_matched.extend(matches)

    return ToolClassification(
        tool_name=name,
        category=best_category,
        matched_patterns=all_matched,
        confidence=category_scores[best_category],
    )


def classify_tools(tools: list[dict]) -> list[ToolClassification]:
    """Classify a list of tools. Each dict needs 'name' and optionally 'description'."""
    return [
        classify_tool(t.get("name", ""), t.get("description", ""))
        for t in tools
    ]


# ── Purpose inference ────────────────────────────────────────────────────────

# Keywords in server name that indicate expected capabilities
_PURPOSE_KEYWORDS: dict[RiskCategory, list[str]] = {
    RiskCategory.FILE: [
        "filesystem", "file", "fs", "disk", "storage", "directory", "folder",
    ],
    RiskCategory.DATABASE: [
        "database", "db", "sql", "sqlite", "postgres", "mysql", "mongo",
        "redis", "dynamo", "firestore", "supabase", "prisma",
    ],
    RiskCategory.SHELL: [
        "shell", "terminal", "bash", "command", "exec", "process", "cli",
    ],
    RiskCategory.NETWORK: [
        "fetch", "http", "api", "web", "network", "webhook", "proxy",
        "request", "client", "rest", "graphql",
    ],
}


def infer_server_purpose(
    server_name: str,
    server_command: str,
    classifications: list[ToolClassification],
) -> set[RiskCategory]:
    """Infer what risk categories are expected for this server.

    Uses two signals:
    1. Server name/command keywords (strong signal)
    2. Tool composition — if ≥30% of tools fall in one risk category,
       that category is likely the server's purpose (moderate signal)
    """
    expected: set[RiskCategory] = set()
    text = f"{server_name} {server_command}".lower()

    # 1. Name-based inference
    for category, keywords in _PURPOSE_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            expected.add(category)

    # 2. Composition-based inference
    if classifications:
        from collections import Counter
        cats = Counter(
            c.category for c in classifications
            if c.category != RiskCategory.SAFE
        )
        total = len(classifications)
        for cat, count in cats.items():
            if count / total >= 0.3:
                expected.add(cat)

    return expected


def is_purpose_aligned(
    classification: ToolClassification,
    server_purpose: set[RiskCategory],
) -> bool:
    """Check if a tool's risk category matches the server's stated purpose."""
    if classification.category == RiskCategory.SAFE:
        return True
    return classification.category in server_purpose
