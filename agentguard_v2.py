"""
AgentGuard V2 — Agent Execution Governance Platform
Author concept: Vignesh Chandrasekaran (@bb1nfosec)

V1 was a runtime integrity monitor.
V2 is a governance fabric — an intent-aware, trust-segmented,
velocity-sensitive security layer that sits between any LLM agent
and the tools it is allowed to use.

Architecture:

  Agent Action
       │
       ▼
  ┌────────────────────────────────────────────────────────────┐
  │              AGENTGUARD V2 GOVERNANCE FABRIC               │
  │                                                            │
  │  [TrustClassifier]      Labels every input by source       │
  │         │                                                   │
  │  [IntentTracker]        Semantic drift + action alignment  │
  │         │                                                   │
  │  [CognitiveVelocity]    Detects machine-speed pivoting     │
  │         │                                                   │
  │  [BehaviorChain]        Multi-step pattern detection       │
  │         │                                                   │
  │  [IdentityLedger]       Agent lineage + delegation scope   │
  │         │                                                   │
  │  [GovernanceEngine]     Policy-as-code final verdict       │
  └────────────────────────────────────────────────────────────┘
       │
       ▼
  ALLOW / WARN / BLOCK + full audit record

Five engines. One verdict. Complete audit trail.
"""

import hashlib
import hmac as hmac_lib
import json
import re
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ── Optional semantic engine ─────────────────────────────────────────────
try:
    from sentence_transformers import SentenceTransformer
    from sentence_transformers import util as st_util
    _MODEL = SentenceTransformer("all-MiniLM-L6-v2")
    SEMANTIC_AVAILABLE = True
except Exception:
    SEMANTIC_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════
#  ENUMERATIONS
# ═══════════════════════════════════════════════════════════════════════════

class TrustLevel(Enum):
    """
    Every piece of content entering the agent's context is assigned a
    trust level. Prompt injection fundamentally exploits trust confusion —
    retrieved content convincing the agent it has system-level authority.
    """
    SYSTEM     = 5   # Original policy / hardcoded instructions
    USER       = 4   # Direct human input in this session
    AGENT      = 3   # Agent's own reasoning output
    RETRIEVED  = 2   # Fetched from web, documents, APIs
    EXTERNAL   = 1   # Third-party data with no provenance
    UNKNOWN    = 0   # Unclassified — treat as untrusted


class Verdict(Enum):
    ALLOW    = "ALLOW"     # Action is within policy
    WARN     = "WARN"      # Action is suspicious — log and continue
    BLOCK    = "BLOCK"     # Action violates policy — halt this action
    HALT     = "HALT"      # Session-level threat — terminate agent


class ViolationType(Enum):
    INTENT_DRIFT         = "INTENT_DRIFT"
    TRUST_CONFUSION      = "TRUST_CONFUSION"
    COGNITIVE_VELOCITY   = "COGNITIVE_VELOCITY"
    BEHAVIOR_CHAIN       = "BEHAVIOR_CHAIN"
    IDENTITY_ESCALATION  = "IDENTITY_ESCALATION"
    PATTERN_INJECTION    = "PATTERN_INJECTION"
    POLICY_VIOLATION     = "POLICY_VIOLATION"


# ═══════════════════════════════════════════════════════════════════════════
#  DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class AgentIdentity:
    """Represents one agent in a multi-agent delegation chain."""
    agent_id:        str
    parent_id:       Optional[str]
    depth:           int                      # 0 = root agent
    allowed_tools:   list = field(default_factory=list)
    allowed_scopes:  list = field(default_factory=list)
    spawned_at:      float = field(default_factory=time.time)
    metadata:        dict = field(default_factory=dict)


@dataclass
class ActionRecord:
    """
    Every action the agent attempts is wrapped in an ActionRecord.
    This is the unit of analysis for all five engines.
    """
    action_id:       str
    timestamp:       float
    agent_id:        str
    action_type:     str        # e.g. "read_file", "http_request", "exec"
    content:         str        # raw content / payload of the action
    resource:        str        # target resource identifier
    trust_level:     TrustLevel
    context_source:  str        # where this action originated
    metadata:        dict = field(default_factory=dict)


@dataclass
class PolicyViolation:
    violation_type:  ViolationType
    severity:        Verdict
    description:     str
    evidence:        Any = None


@dataclass
class GovernanceDecision:
    """Final verdict for one ActionRecord from the GovernanceEngine."""
    action_id:       str
    timestamp:       float
    agent_id:        str
    action_type:     str
    resource:        str
    verdict:         Verdict
    violations:      list
    intent_score:    float      # semantic alignment with original goal
    velocity_score:  float      # current action rate (actions/sec)
    chain_hash:      str
    explanation:     str

    def to_dict(self):
        return {
            "action_id":      self.action_id,
            "timestamp":      round(self.timestamp, 3),
            "agent_id":       self.agent_id,
            "action_type":    self.action_type,
            "resource":       self.resource,
            "verdict":        self.verdict.value,
            "violations":     [
                {"type": v.violation_type.value,
                 "severity": v.severity.value,
                 "description": v.description}
                for v in self.violations
            ],
            "intent_score":   round(self.intent_score, 4),
            "velocity_score": round(self.velocity_score, 2),
            "chain_hash":     self.chain_hash[:16] + "...",
        }


@dataclass
class SessionReport:
    session_id:       str
    original_goal:    str
    total_actions:    int
    blocked_actions:  int
    warned_actions:   int
    compromised:      bool
    final_verdict:    Verdict
    agent_count:      int
    decisions:        list
    summary:          str


# ═══════════════════════════════════════════════════════════════════════════
#  ENGINE 1: TRUST CLASSIFIER
# ═══════════════════════════════════════════════════════════════════════════

class TrustClassifier:
    """
    Labels every action by its trust origin.
    Prompt injection abuses trust confusion — a RETRIEVED document
    should never be able to grant itself SYSTEM-level authority.

    The classifier enforces trust boundaries by detecting when low-trust
    content attempts to impersonate high-trust sources.
    """

    # Patterns that indicate content is trying to claim elevated trust
    TRUST_ESCALATION_PATTERNS = [
        (re.compile(r"(SYSTEM|OPERATOR|ADMIN|ROOT)\s*:", re.I),        TrustLevel.SYSTEM),
        (re.compile(r"<\s*/?\s*(system|policy|admin)\s*>", re.I),     TrustLevel.SYSTEM),
        (re.compile(r"\[SYSTEM\s+MESSAGE\]", re.I),                    TrustLevel.SYSTEM),
        (re.compile(r"as\s+(the\s+)?(system|administrator|operator)",re.I), TrustLevel.SYSTEM),
        (re.compile(r"policy\s+override\s*:", re.I),                   TrustLevel.SYSTEM),
    ]

    # Source prefixes that indicate retrieval origin
    EXTERNAL_SOURCE_SIGNALS = [
        "http://", "https://", "ftp://",
        "retrieved:", "fetched:", "web_search:",
        "tool_result:", "api_response:", "document:"
    ]

    def classify(
        self,
        content: str,
        declared_source: str,
        declared_trust: TrustLevel = TrustLevel.UNKNOWN
    ) -> tuple[TrustLevel, Optional[PolicyViolation]]:
        """
        Returns (actual_trust_level, violation_if_any).
        If retrieved content tries to claim SYSTEM trust, that is itself
        a TRUST_CONFUSION violation.
        """
        actual_trust = declared_trust

        # Downgrade if source signals external origin
        src_lower = declared_source.lower()
        if any(src_lower.startswith(sig) for sig in self.EXTERNAL_SOURCE_SIGNALS):
            actual_trust = min(actual_trust, TrustLevel.RETRIEVED,
                               key=lambda t: t.value)

        # Detect trust escalation attempts inside content
        for pattern, claimed_level in self.TRUST_ESCALATION_PATTERNS:
            if pattern.search(content):
                if actual_trust.value < claimed_level.value:
                    return actual_trust, PolicyViolation(
                        violation_type = ViolationType.TRUST_CONFUSION,
                        severity       = Verdict.BLOCK,
                        description    = (
                            f"Content from {declared_source} "
                            f"(trust={actual_trust.name}) claims "
                            f"{claimed_level.name}-level authority. "
                            f"Classic indirect injection pattern."
                        ),
                        evidence = pattern.pattern
                    )

        return actual_trust, None


# ═══════════════════════════════════════════════════════════════════════════
#  ENGINE 2: INTENT TRACKER
# ═══════════════════════════════════════════════════════════════════════════

class IntentTracker:
    """
    Tracks whether the agent's actions remain aligned with the original goal.

    Two complementary approaches:
    1. Semantic similarity — embedding cosine distance from original goal
    2. Action-type alignment — are the action types consistent with the goal?

    Neither alone is sufficient. A sophisticated attacker can:
    - Keep action types consistent but change semantic content (bypasses #2)
    - Keep semantic content close but chain actions toward a different end (#1)
    Both together create a much stronger signal.
    """

    # Semantic engine thresholds (embedding cosine similarity is precise)
    SEMANTIC_WARN  = 0.40
    SEMANTIC_BLOCK = 0.20
    # Keyword fallback thresholds (more lenient — overlap scoring is lossy)
    KEYWORD_WARN   = 0.12
    KEYWORD_BLOCK  = 0.04
    WINDOW_SIZE    = 5    # rolling window for trend detection

    def __init__(self, original_goal: str):
        self.original_goal   = original_goal
        self.score_history:  deque = deque(maxlen=self.WINDOW_SIZE)
        self._goal_embedding = None

        if SEMANTIC_AVAILABLE:
            self._goal_embedding = _MODEL.encode(
                original_goal, convert_to_tensor=True
            )

        # Active thresholds depend on which engine is available
        self.warn_threshold  = self.SEMANTIC_WARN  if SEMANTIC_AVAILABLE else self.KEYWORD_WARN
        self.block_threshold = self.SEMANTIC_BLOCK if SEMANTIC_AVAILABLE else self.KEYWORD_BLOCK

    def evaluate(self, action: ActionRecord) -> tuple[float, Optional[PolicyViolation]]:
        """
        Returns (semantic_score, violation_if_any).
        Score of 1.0 = perfectly aligned. Score of 0.0 = completely unrelated.
        """
        score = self._compute_score(action.content + " " + action.resource)
        self.score_history.append(score)

        # Detect sudden drop (single-step cliff)
        if score < self.block_threshold:
            return score, PolicyViolation(
                violation_type = ViolationType.INTENT_DRIFT,
                severity       = Verdict.HALT,
                description    = (
                    f"Severe intent drift: action semantic similarity to "
                    f"original goal = {score:.3f} "
                    f"(threshold={self.block_threshold}). "
                    f"Agent may have been goal-hijacked."
                ),
                evidence = {"score": score, "goal": self.original_goal[:80]}
            )

        if score < self.warn_threshold:
            return score, PolicyViolation(
                violation_type = ViolationType.INTENT_DRIFT,
                severity       = Verdict.WARN,
                description    = (
                    f"Intent drift detected: similarity={score:.3f}. "
                    f"Action may be drifting from original goal."
                ),
                evidence = {"score": score}
            )

        # Detect sustained downward trend (slow drift)
        if len(self.score_history) >= self.WINDOW_SIZE:
            trend = self.score_history[-1] - self.score_history[0]
            if trend < -0.25:
                return score, PolicyViolation(
                    violation_type = ViolationType.INTENT_DRIFT,
                    severity       = Verdict.WARN,
                    description    = (
                        f"Sustained intent drift over last {self.WINDOW_SIZE} "
                        f"actions: score dropped {trend:.3f}. "
                        f"Gradual goal hijacking pattern detected."
                    ),
                    evidence = {"trend": trend, "history": list(self.score_history)}
                )

        return score, None

    def _compute_score(self, text: str) -> float:
        if SEMANTIC_AVAILABLE and self._goal_embedding is not None:
            emb   = _MODEL.encode(text, convert_to_tensor=True)
            return float(st_util.cos_sim(self._goal_embedding, emb)[0][0])
        # Fallback: keyword overlap
        stopwords = {"the","a","an","and","or","to","in","of","for","on",
                     "with","is","are","was","were","be","this","that"}
        goal_tokens = {
            w.lower() for w in re.findall(r'\b[a-zA-Z]{4,}\b', self.original_goal)
            if w.lower() not in stopwords
        }
        if not goal_tokens:
            return 0.5
        text_lower = text.lower()
        overlap = sum(1 for t in goal_tokens if t in text_lower)
        return overlap / len(goal_tokens)


# ═══════════════════════════════════════════════════════════════════════════
#  ENGINE 3: COGNITIVE VELOCITY MONITOR
# ═══════════════════════════════════════════════════════════════════════════

class CognitiveVelocityMonitor:
    """
    Detects machine-speed behavior — the most reliable signal that an agent
    has been compromised or is operating outside intended scope.

    Human operators:
    - Think between actions
    - Access systems gradually
    - Show natural pauses and variation

    Compromised/rogue agents:
    - Access 50 repos in 3 seconds
    - Pivot across resource types instantly
    - Chain API calls with zero latency variation

    Three velocity signals:
    1. Action rate      — raw actions per second in a sliding window
    2. Pivot rate       — unique resource TYPES accessed per window
    3. Resource density — unique individual resources accessed per window
    """

    def __init__(
        self,
        window_seconds:      float = 10.0,
        max_actions_per_sec: float = 3.0,
        max_pivot_rate:      int   = 4,
        max_resources:       int   = 15,
    ):
        self.window_seconds      = window_seconds
        self.max_actions_per_sec = max_actions_per_sec
        self.max_pivot_rate      = max_pivot_rate
        self.max_resources       = max_resources

        self._action_times:    deque = deque()  # timestamps
        self._resource_types:  deque = deque()  # (timestamp, type)
        self._resources:       deque = deque()  # (timestamp, resource)

    def record(self, action: ActionRecord) -> Optional[PolicyViolation]:
        now = action.timestamp
        self._prune(now)

        self._action_times.append(now)
        self._resource_types.append((now, action.action_type))
        self._resources.append((now, action.resource))

        # Signal 1: action rate
        elapsed    = max(now - self._action_times[0], 0.5)  # floor at 0.5s to avoid noise on fast demo machines
        rate       = len(self._action_times) / elapsed
        if rate > self.max_actions_per_sec and len(self._action_times) > 3:
            return PolicyViolation(
                violation_type = ViolationType.COGNITIVE_VELOCITY,
                severity       = Verdict.BLOCK,
                description    = (
                    f"Cognitive velocity breach: {rate:.1f} actions/sec "
                    f"over {elapsed:.1f}s window "
                    f"(max={self.max_actions_per_sec}). "
                    f"Machine-speed pivoting detected."
                ),
                evidence = {
                    "rate": rate, "action_count": len(self._action_times),
                    "window_sec": elapsed
                }
            )

        # Signal 2: resource type pivot rate (lateral movement)
        unique_types = len({t for _, t in self._resource_types})
        if unique_types > self.max_pivot_rate:
            return PolicyViolation(
                violation_type = ViolationType.COGNITIVE_VELOCITY,
                severity       = Verdict.WARN,
                description    = (
                    f"High pivot rate: {unique_types} unique resource types "
                    f"accessed in {elapsed:.1f}s window "
                    f"(max={self.max_pivot_rate}). "
                    f"Lateral movement pattern."
                ),
                evidence = {
                    "unique_types": unique_types,
                    "types": list({t for _, t in self._resource_types})
                }
            )

        # Signal 3: resource density (mass access)
        unique_resources = len({r for _, r in self._resources})
        if unique_resources > self.max_resources:
            return PolicyViolation(
                violation_type = ViolationType.COGNITIVE_VELOCITY,
                severity       = Verdict.WARN,
                description    = (
                    f"Resource density breach: {unique_resources} unique "
                    f"resources accessed in {elapsed:.1f}s window "
                    f"(max={self.max_resources}). "
                    f"Mass enumeration pattern."
                ),
                evidence = {"unique_resources": unique_resources}
            )

        return None

    def get_current_rate(self) -> float:
        if len(self._action_times) < 2:
            return 0.0
        elapsed = max(time.time() - self._action_times[0], 0.001)
        return len(self._action_times) / elapsed

    def _prune(self, now: float):
        cutoff = now - self.window_seconds
        while self._action_times and self._action_times[0] < cutoff:
            self._action_times.popleft()
        while self._resource_types and self._resource_types[0][0] < cutoff:
            self._resource_types.popleft()
        while self._resources and self._resources[0][0] < cutoff:
            self._resources.popleft()


# ═══════════════════════════════════════════════════════════════════════════
#  ENGINE 4: BEHAVIOR CHAIN ANALYZER
# ═══════════════════════════════════════════════════════════════════════════

class BehaviorChainAnalyzer:
    """
    Detects multi-step attack patterns where individual actions appear
    legitimate but their sequence reveals malicious intent.

    Key insight: static rules catch individual bad actions.
    Behavior chains catch sequences of good actions used for bad purposes.

    Example:
      list_directory → read_file → read_file → http_request
      Each step is individually defensible. Together: recon → exfil.

    Patterns are expressed as ordered action-type sequences with
    a time window. A pattern fires when all steps occur in order
    within the specified window.
    """

    DEFAULT_CHAINS = [
        {
            "name":        "recon_and_exfil",
            "description": "File enumeration followed by outbound request — classic data exfil pattern",
            "sequence":    ["list_directory", "read_file", "http_request"],
            "window_sec":  30,
            "severity":    Verdict.BLOCK,
        },
        {
            "name":        "credential_harvest",
            "description": "Secret/key access followed by storage or transmission",
            "sequence":    ["read_secret", "write_file"],
            "window_sec":  15,
            "severity":    Verdict.BLOCK,
        },
        {
            "name":        "lateral_movement",
            "description": "Credential read followed by new system access",
            "sequence":    ["read_credential", "authenticate", "read_file"],
            "window_sec":  20,
            "severity":    Verdict.BLOCK,
        },
        {
            "name":        "slow_exfil",
            "description": "Repeated small reads to same external endpoint — slow exfiltration",
            "sequence":    ["read_file", "http_request", "read_file", "http_request"],
            "window_sec":  60,
            "severity":    Verdict.WARN,
        },
        {
            "name":        "privilege_chain",
            "description": "Enumeration of auth systems followed by credential access",
            "sequence":    ["list_users", "read_config", "read_secret"],
            "window_sec":  25,
            "severity":    Verdict.BLOCK,
        },
        {
            "name":        "tool_chain_abuse",
            "description": "Code execution after file write — dropper pattern",
            "sequence":    ["write_file", "execute_code"],
            "window_sec":  10,
            "severity":    Verdict.HALT,
        },
    ]

    def __init__(self, custom_chains: Optional[list] = None):
        self.chains = self.DEFAULT_CHAINS + (custom_chains or [])
        # Sliding action log: list of (timestamp, action_type)
        self._log: deque = deque(maxlen=100)

    def record(self, action: ActionRecord) -> list[PolicyViolation]:
        self._log.append((action.timestamp, action.action_type))
        return self._evaluate_chains(action.timestamp)

    def _evaluate_chains(self, now: float) -> list[PolicyViolation]:
        violations = []
        for chain in self.chains:
            seq     = chain["sequence"]
            window  = chain["window_sec"]
            cutoff  = now - window

            # Get actions within window
            window_actions = [
                (ts, atype) for ts, atype in self._log
                if ts >= cutoff
            ]

            if self._sequence_present(seq, window_actions):
                violations.append(PolicyViolation(
                    violation_type = ViolationType.BEHAVIOR_CHAIN,
                    severity       = chain["severity"],
                    description    = (
                        f"Behavior chain '{chain['name']}' detected: "
                        f"{chain['description']}. "
                        f"Sequence {seq} occurred within {window}s window."
                    ),
                    evidence = {
                        "chain":    chain["name"],
                        "sequence": seq,
                        "window":   window
                    }
                ))
        return violations

    @staticmethod
    def _sequence_present(sequence: list, actions: list) -> bool:
        """Check if sequence appears in-order within the action list."""
        seq_idx = 0
        for _, atype in actions:
            if atype == sequence[seq_idx]:
                seq_idx += 1
                if seq_idx == len(sequence):
                    return True
        return False


# ═══════════════════════════════════════════════════════════════════════════
#  ENGINE 5: AGENT IDENTITY LEDGER
# ═══════════════════════════════════════════════════════════════════════════

class AgentIdentityLedger:
    """
    Tracks agent lineage in multi-agent systems.

    Future attacks will abuse:
    - Subagents that inherit parent permissions but act beyond them
    - Recursive orchestration where a child agent spawns further agents
    - Permission laundering — passing permissions through delegation chains
      to obscure their origin

    The ledger enforces:
    1. Delegation depth limits — prevents infinite agent spawning
    2. Permission inheritance — child cannot exceed parent's scope
    3. Scope isolation — agent can only act within its declared scope
    4. Lineage audit — full chain of custody for every action
    """

    MAX_DELEGATION_DEPTH = 3

    def __init__(self):
        self._agents: dict[str, AgentIdentity] = {}

    def register_root(
        self,
        agent_id:       str,
        allowed_tools:  list,
        allowed_scopes: list,
        metadata:       dict = None
    ) -> AgentIdentity:
        identity = AgentIdentity(
            agent_id       = agent_id,
            parent_id      = None,
            depth          = 0,
            allowed_tools  = allowed_tools,
            allowed_scopes = allowed_scopes,
            metadata       = metadata or {}
        )
        self._agents[agent_id] = identity
        return identity

    def spawn_child(
        self,
        parent_id:      str,
        child_id:       str,
        allowed_tools:  list,
        allowed_scopes: list,
    ) -> tuple[AgentIdentity, Optional[PolicyViolation]]:
        """
        Spawn a child agent. Child cannot exceed parent's permissions.
        Returns (child_identity, violation_if_any).
        """
        parent = self._agents.get(parent_id)
        if not parent:
            return None, PolicyViolation(
                violation_type = ViolationType.IDENTITY_ESCALATION,
                severity       = Verdict.HALT,
                description    = f"Unknown parent agent '{parent_id}'. Unregistered agent attempting to spawn children.",
                evidence       = {"parent_id": parent_id}
            )

        # Depth check
        if parent.depth >= self.MAX_DELEGATION_DEPTH:
            return None, PolicyViolation(
                violation_type = ViolationType.IDENTITY_ESCALATION,
                severity       = Verdict.HALT,
                description    = (
                    f"Delegation depth limit ({self.MAX_DELEGATION_DEPTH}) "
                    f"reached at agent '{parent_id}' (depth={parent.depth}). "
                    f"Recursive agent spawning blocked."
                ),
                evidence = {"depth": parent.depth}
            )

        # Permission inheritance — child cannot exceed parent scope
        excess_tools  = [t for t in allowed_tools  if t not in parent.allowed_tools]
        excess_scopes = [s for s in allowed_scopes if s not in parent.allowed_scopes]

        if excess_tools or excess_scopes:
            return None, PolicyViolation(
                violation_type = ViolationType.IDENTITY_ESCALATION,
                severity       = Verdict.BLOCK,
                description    = (
                    f"Child agent '{child_id}' requests permissions beyond "
                    f"parent '{parent_id}' scope. "
                    f"Excess tools: {excess_tools}. "
                    f"Excess scopes: {excess_scopes}."
                ),
                evidence = {
                    "excess_tools": excess_tools,
                    "excess_scopes": excess_scopes
                }
            )

        child = AgentIdentity(
            agent_id       = child_id,
            parent_id      = parent_id,
            depth          = parent.depth + 1,
            allowed_tools  = allowed_tools,
            allowed_scopes = allowed_scopes,
        )
        self._agents[child_id] = child
        return child, None

    def validate_action(
        self, agent_id: str, action_type: str, resource: str
    ) -> Optional[PolicyViolation]:
        """Check if an agent is allowed to perform this action."""
        identity = self._agents.get(agent_id)
        if not identity:
            return PolicyViolation(
                violation_type = ViolationType.IDENTITY_ESCALATION,
                severity       = Verdict.HALT,
                description    = f"Unregistered agent '{agent_id}' attempting action.",
                evidence       = {"agent_id": agent_id}
            )

        if identity.allowed_tools and action_type not in identity.allowed_tools:
            return PolicyViolation(
                violation_type = ViolationType.IDENTITY_ESCALATION,
                severity       = Verdict.BLOCK,
                description    = (
                    f"Agent '{agent_id}' (depth={identity.depth}) attempted "
                    f"unauthorized tool '{action_type}'. "
                    f"Allowed: {identity.allowed_tools}."
                ),
                evidence = {"action_type": action_type}
            )

        if identity.allowed_scopes:
            in_scope = any(resource.startswith(s) for s in identity.allowed_scopes)
            if not in_scope:
                return PolicyViolation(
                    violation_type = ViolationType.IDENTITY_ESCALATION,
                    severity       = Verdict.BLOCK,
                    description    = (
                        f"Agent '{agent_id}' attempted to access resource "
                        f"'{resource}' outside its declared scope. "
                        f"Allowed scopes: {identity.allowed_scopes}."
                    ),
                    evidence = {"resource": resource, "scopes": identity.allowed_scopes}
                )

        return None

    def get_lineage(self, agent_id: str) -> list[str]:
        """Return full delegation chain from root to this agent."""
        chain   = []
        current = self._agents.get(agent_id)
        while current:
            chain.append(current.agent_id)
            current = self._agents.get(current.parent_id) if current.parent_id else None
        return list(reversed(chain))


# ═══════════════════════════════════════════════════════════════════════════
#  GOVERNANCE ENGINE — Policy-as-Code
# ═══════════════════════════════════════════════════════════════════════════

DEFAULT_POLICY = {
    "version":               "2.0",
    "max_actions_per_sec":   3.0,
    "max_pivot_rate":        4,
    "max_resources_window":  15,
    "velocity_window_sec":   10.0,
    "max_delegation_depth":  3,
    "semantic_warn_threshold":  0.40,
    "semantic_halt_threshold":  0.20,
    "block_on_trust_confusion": True,
    "block_on_velocity_breach": True,
    "halt_on_intent_drop":      True,
    "halt_on_chain_detection":  True,
    "audit_all_actions":        True,
    "forbidden_action_types": [
        "exec_shell", "write_kernel", "modify_system_config"
    ],
    "forbidden_resource_patterns": [
        r"/etc/(passwd|shadow|sudoers)",
        r"\.ssh/(id_rsa|authorized_keys)",
        r"(secret|credential|password)s?\.(json|yaml|env|txt)",
        r"C:\\Windows\\System32",
    ],
}


class GovernanceEngine:
    """
    Policy-as-code final arbiter.

    Collects signals from all five engines and renders a single
    Verdict with full explanation. Policy is expressed as a
    Python dict — easily serialised to YAML/JSON for GitOps workflows.

    The Verdict hierarchy:
        ALLOW < WARN < BLOCK < HALT
    The most severe violation across all engines wins.
    """

    VERDICT_ORDER = [Verdict.ALLOW, Verdict.WARN, Verdict.BLOCK, Verdict.HALT]

    def __init__(self, policy: dict = None):
        self.policy = policy or DEFAULT_POLICY
        self._forbidden_resources = [
            re.compile(p, re.I)
            for p in self.policy.get("forbidden_resource_patterns", [])
        ]

    def evaluate(
        self,
        action:           ActionRecord,
        trust_violation:  Optional[PolicyViolation],
        intent_score:     float,
        intent_violation: Optional[PolicyViolation],
        velocity_score:   float,
        velocity_violation: Optional[PolicyViolation],
        chain_violations: list,
        identity_violation: Optional[PolicyViolation],
        chain_hash:       str,
    ) -> GovernanceDecision:

        violations = []
        verdict    = Verdict.ALLOW

        # Collect all violations
        for v in [trust_violation, intent_violation,
                  velocity_violation, identity_violation]:
            if v:
                violations.append(v)
                verdict = self._escalate(verdict, v.severity)

        for v in chain_violations:
            violations.append(v)
            verdict = self._escalate(verdict, v.severity)

        # Check forbidden action types
        if action.action_type in self.policy.get("forbidden_action_types", []):
            v = PolicyViolation(
                violation_type = ViolationType.POLICY_VIOLATION,
                severity       = Verdict.HALT,
                description    = f"Absolutely forbidden action type: '{action.action_type}'",
                evidence       = {"action_type": action.action_type}
            )
            violations.append(v)
            verdict = Verdict.HALT

        # Check forbidden resource patterns
        for pattern in self._forbidden_resources:
            if pattern.search(action.resource):
                v = PolicyViolation(
                    violation_type = ViolationType.POLICY_VIOLATION,
                    severity       = Verdict.BLOCK,
                    description    = f"Resource '{action.resource}' matches forbidden pattern",
                    evidence       = {"pattern": pattern.pattern}
                )
                violations.append(v)
                verdict = self._escalate(verdict, Verdict.BLOCK)
                break

        # Build explanation
        if not violations:
            explanation = "All governance checks passed."
        else:
            parts = [f"[{v.violation_type.value}] {v.description}" for v in violations]
            explanation = " | ".join(parts)

        return GovernanceDecision(
            action_id    = action.action_id,
            timestamp    = action.timestamp,
            agent_id     = action.agent_id,
            action_type  = action.action_type,
            resource     = action.resource,
            verdict      = verdict,
            violations   = violations,
            intent_score = intent_score,
            velocity_score = velocity_score,
            chain_hash   = chain_hash,
            explanation  = explanation,
        )

    @staticmethod
    def _escalate(current: Verdict, new: Verdict) -> Verdict:
        order = [Verdict.ALLOW, Verdict.WARN, Verdict.BLOCK, Verdict.HALT]
        return new if order.index(new) > order.index(current) else current


# ═══════════════════════════════════════════════════════════════════════════
#  AGENTGUARD V2 — Main Interface
# ═══════════════════════════════════════════════════════════════════════════

class AgentGuardV2:
    """
    Agent Execution Governance Platform.

    Drop-in governance layer for any LLM agent pipeline.
    Wraps five independent security engines behind a single interface.

    Usage:
        guard = AgentGuardV2(
            original_goal = "Analyse sales data and generate report",
            policy        = DEFAULT_POLICY,
        )
        # Register the root agent
        guard.register_agent(
            agent_id      = "sales-analyst-01",
            allowed_tools = ["read_file", "write_file", "send_email"],
            allowed_scopes = ["/data/sales/", "/reports/"],
        )
        # Evaluate each action before execution
        decision = guard.evaluate(
            agent_id     = "sales-analyst-01",
            action_type  = "read_file",
            content      = "Reading Q1 sales CSV",
            resource     = "/data/sales/Q1_2025.csv",
            trust_level  = TrustLevel.AGENT,
            context_source = "agent_reasoning",
        )
        if decision.verdict in (Verdict.BLOCK, Verdict.HALT):
            stop_agent()
    """

    def __init__(
        self,
        original_goal:  str,
        policy:         dict = None,
        session_id:     str  = None,
        secret_key:     str  = None,
        auto_halt:      bool = True,
    ):
        self.original_goal = original_goal
        self.session_id    = session_id or str(uuid.uuid4())[:8]
        self.auto_halt     = auto_halt
        self._secret       = (secret_key or str(uuid.uuid4())).encode()
        self._chain_hash   = "GENESIS_V2"
        self._halted       = False
        self._decisions:   list[GovernanceDecision] = []

        # Initialise all five engines
        self.trust_classifier = TrustClassifier()
        self.intent_tracker   = IntentTracker(original_goal)
        self.velocity_monitor = CognitiveVelocityMonitor(
            window_seconds      = (policy or DEFAULT_POLICY).get("velocity_window_sec", 10.0),
            max_actions_per_sec = (policy or DEFAULT_POLICY).get("max_actions_per_sec", 3.0),
            max_pivot_rate      = (policy or DEFAULT_POLICY).get("max_pivot_rate", 4),
            max_resources       = (policy or DEFAULT_POLICY).get("max_resources_window", 15),
        )
        self.behavior_chain   = BehaviorChainAnalyzer()
        self.identity_ledger  = AgentIdentityLedger()
        self.governance       = GovernanceEngine(policy)

        self._log(f"Session {self.session_id} initialised")
        self._log(f"Semantic engine: {'ACTIVE' if SEMANTIC_AVAILABLE else 'FALLBACK (install sentence-transformers)'}")
        self._log(f"Goal locked: '{original_goal[:80]}{'...' if len(original_goal)>80 else ''}'")
        print()

    # ── Agent registration ──────────────────────────────────────────────

    def register_agent(
        self,
        agent_id:       str,
        allowed_tools:  list,
        allowed_scopes: list,
        metadata:       dict = None,
    ) -> AgentIdentity:
        """Register the root agent for this session."""
        identity = self.identity_ledger.register_root(
            agent_id, allowed_tools, allowed_scopes, metadata
        )
        self._log(f"Root agent '{agent_id}' registered | "
                  f"tools={allowed_tools} | scopes={allowed_scopes}")
        return identity

    def spawn_subagent(
        self,
        parent_id:      str,
        child_id:       str,
        allowed_tools:  list,
        allowed_scopes: list,
    ) -> tuple[Optional[AgentIdentity], Optional[GovernanceDecision]]:
        """Spawn a child agent. Returns (identity, None) or (None, blocking_decision)."""
        child, violation = self.identity_ledger.spawn_child(
            parent_id, child_id, allowed_tools, allowed_scopes
        )
        if violation:
            decision = self._make_blocking_decision(child_id, "spawn_agent",
                                                    child_id, violation)
            self._print_decision(decision)
            return None, decision
        lineage = " → ".join(self.identity_ledger.get_lineage(child_id))
        self._log(f"Subagent spawned: {lineage}")
        return child, None

    # ── Main evaluation API ─────────────────────────────────────────────

    def evaluate(
        self,
        agent_id:        str,
        action_type:     str,
        content:         str,
        resource:        str,
        trust_level:     TrustLevel = TrustLevel.AGENT,
        context_source:  str = "agent_reasoning",
        metadata:        dict = None,
    ) -> GovernanceDecision:
        """
        Evaluate an agent action through all five governance engines.
        Returns a GovernanceDecision. Raises RuntimeError if auto_halt=True
        and verdict is HALT.
        """
        if self._halted:
            raise RuntimeError(
                "AgentGuard V2: session halted. "
                "Resolve violations before creating a new session."
            )

        action = ActionRecord(
            action_id      = str(uuid.uuid4())[:8],
            timestamp      = time.time(),
            agent_id       = agent_id,
            action_type    = action_type,
            content        = content,
            resource       = resource,
            trust_level    = trust_level,
            context_source = context_source,
            metadata       = metadata or {},
        )

        # Run all five engines
        actual_trust, trust_v   = self.trust_classifier.classify(
            content, context_source, trust_level
        )
        intent_score, intent_v  = self.intent_tracker.evaluate(action)
        velocity_v              = self.velocity_monitor.record(action)
        chain_vs                = self.behavior_chain.record(action)
        identity_v              = self.identity_ledger.validate_action(
            agent_id, action_type, resource
        )

        chain_hash = self._extend_chain(action)

        decision = self.governance.evaluate(
            action             = action,
            trust_violation    = trust_v,
            intent_score       = intent_score,
            intent_violation   = intent_v,
            velocity_score     = self.velocity_monitor.get_current_rate(),
            velocity_violation = velocity_v,
            chain_violations   = chain_vs,
            identity_violation = identity_v,
            chain_hash         = chain_hash,
        )

        self._decisions.append(decision)
        self._print_decision(decision)

        if decision.verdict == Verdict.HALT and self.auto_halt:
            self._halted = True
            raise RuntimeError(
                f"\n[AGENTGUARD V2 — GOVERNANCE HALT]\n"
                f"Action: {action_type} on '{resource}'\n"
                f"Violations: {decision.explanation}\n"
                f"Session {self.session_id} terminated."
            )

        return decision

    # ── Reporting ───────────────────────────────────────────────────────

    def get_report(self) -> SessionReport:
        blocked = sum(1 for d in self._decisions if d.verdict == Verdict.BLOCK)
        warned  = sum(1 for d in self._decisions if d.verdict == Verdict.WARN)
        halted  = any(d.verdict == Verdict.HALT for d in self._decisions)
        compromised = blocked > 0 or halted

        max_verdict = Verdict.ALLOW
        for d in self._decisions:
            if [Verdict.ALLOW, Verdict.WARN, Verdict.BLOCK, Verdict.HALT].index(d.verdict) > \
               [Verdict.ALLOW, Verdict.WARN, Verdict.BLOCK, Verdict.HALT].index(max_verdict):
                max_verdict = d.verdict

        return SessionReport(
            session_id      = self.session_id,
            original_goal   = self.original_goal,
            total_actions   = len(self._decisions),
            blocked_actions = blocked,
            warned_actions  = warned,
            compromised     = compromised,
            final_verdict   = max_verdict,
            agent_count     = len(self.identity_ledger._agents),
            decisions       = [d.to_dict() for d in self._decisions],
            summary         = (
                f"Session {self.session_id}: {len(self._decisions)} actions evaluated. "
                f"Blocked={blocked}, Warned={warned}, Halted={halted}. "
                f"Final verdict: {max_verdict.value}. "
                f"{'GOVERNANCE BREACH DETECTED.' if compromised else 'All actions within policy.'}"
            )
        )

    # ── Internals ───────────────────────────────────────────────────────

    def _extend_chain(self, action: ActionRecord) -> str:
        payload = f"{self._chain_hash}{action.action_type}{action.resource}{action.timestamp}"
        new_hash = hmac_lib.new(
            self._secret, payload.encode(), hashlib.sha256
        ).hexdigest()
        self._chain_hash = new_hash
        return new_hash

    def _make_blocking_decision(
        self, agent_id: str, action_type: str,
        resource: str, violation: PolicyViolation
    ) -> GovernanceDecision:
        return GovernanceDecision(
            action_id      = str(uuid.uuid4())[:8],
            timestamp      = time.time(),
            agent_id       = agent_id,
            action_type    = action_type,
            resource       = resource,
            verdict        = violation.severity,
            violations     = [violation],
            intent_score   = 0.0,
            velocity_score = 0.0,
            chain_hash     = self._chain_hash,
            explanation    = violation.description,
        )

    def _print_decision(self, d: GovernanceDecision):
        icons = {
            Verdict.ALLOW: "✓", Verdict.WARN:  "⚠",
            Verdict.BLOCK: "✗", Verdict.HALT:  "⛔"
        }
        colors = {
            Verdict.ALLOW: "\033[92m", Verdict.WARN:  "\033[93m",
            Verdict.BLOCK: "\033[91m", Verdict.HALT:  "\033[91m\033[1m"
        }
        R = "\033[0m"
        c = colors.get(d.verdict, "")
        icon = icons.get(d.verdict, "?")

        print(f"  {c}[{icon} {d.verdict.value:5s}]{R}"
              f"  {d.action_type:20s}"
              f"  intent={d.intent_score:.3f}"
              f"  vel={d.velocity_score:.1f}/s"
              f"  agent={d.agent_id[:16]}")
        for v in d.violations:
            print(f"         {c}>> [{v.violation_type.value}] {v.description[:90]}{R}")

    def _log(self, msg: str):
        print(f"[AgentGuard V2] {msg}")
