"""
Attack graph: turns the reconnaissance attack surface and accumulated
findings into a ranked set of next-action hypotheses that guide the
orchestrator.

The graph does not "learn"; it encodes domain rules as node-type groups and
an evidence/session-aware scoring function so the orchestrator is guided by
differentiated scores instead of a flat prior.
"""


# Node-type groups. Recon stores the attack surface under these category keys
# (see state.py attack_surface), and update_attack_graph_from_recon turns each
# category into a node whose ``type`` is that category name. We match
# permissively so both the attack_surface schema (authentication/authorization/
# user_data/transactions) and the looser top-level schema (user/transaction/...)
# resolve to the same groups.
INJECTION_TYPES = {"injection"}
CLIENT_TYPES = {"client_side"}
AUTH_TYPES = {"authentication", "auth", "auth_endpoints"}
USER_RESOURCE_TYPES = {
    "authorization",
    "user_data",
    "transactions",
    "user_endpoints",
    "transaction_endpoints",
    "user",
    "users",
    "transaction",
}


class AttackGraph:
    def __init__(self):
        self.nodes = {}
        self.edges = []
        self.hypotheses = []

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------
    def add_node(self, node_id, node_type, data=None):
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id,
                "type": node_type,
                "data": data or {}
            }

    def add_edge(self, source, target, relation, evidence=None):
        edge = {
            "source": source,
            "target": target,
            "relation": relation,
            "evidence": evidence or {}
        }
        if edge not in self.edges:
            self.edges.append(edge)

    def add_hypothesis(self, source, target, reason, score=0.0):
        self.hypotheses.append({
            "source": source,
            "target": target,
            "reason": reason,
            "score": score
        })

    def get_candidates(self):
        return sorted(
            self.hypotheses,
            key=lambda x: x["score"],
            reverse=True
        )

    # ------------------------------------------------------------------
    # Node-type helpers
    # ------------------------------------------------------------------
    def _nodes_of(self, type_set):
        return [n for n in self.nodes.values() if n["type"] in type_set]

    def _has(self, type_set):
        return any(n["type"] in type_set for n in self.nodes.values())

    @staticmethod
    def _has_session(state):
        """True when any module has produced an authenticated session."""
        return bool(
            state.get("authenticated_session")
            or state.get("sqli_state", {}).get("authenticated_session")
            or state.get("idor_state", {}).get("authenticated_session")
            or (
                isinstance(state.get("pending_chain"), dict)
                and state["pending_chain"].get("authenticated_session")
            )
            or state.get("auth_state", {}).get("session_created_by_module")
        )

    @staticmethod
    def _module_vulnerable(state, category):
        return any(
            isinstance(f, dict)
            and f.get("category") == category
            and f.get("vulnerable") is True
            for f in state.get("findings", [])
        )

    # ------------------------------------------------------------------
    # Hypothesis generation
    # ------------------------------------------------------------------
    def infer_relationships(self):
        """Create one hypothesis per viable module from the discovered nodes."""
        self.hypotheses = []

        injection_nodes = self._nodes_of(INJECTION_TYPES)
        client_nodes = self._nodes_of(CLIENT_TYPES)
        auth_nodes = self._nodes_of(AUTH_TYPES)
        user_nodes = self._nodes_of(USER_RESOURCE_TYPES)

        for injection in injection_nodes:
            self.add_hypothesis(
                source=injection["id"],
                target="sqli_check",
                reason="Injection target discovered during reconnaissance.",
                score=0.0,
            )

        for client in client_nodes:
            self.add_hypothesis(
                source=client["id"],
                target="xss_check",
                reason="Client-side target discovered during reconnaissance.",
                score=0.0,
            )

        for auth in auth_nodes:
            self.add_hypothesis(
                source=auth["id"],
                target="auth",
                reason="Authentication endpoint discovered during reconnaissance.",
                score=0.0,
            )

        # IDOR and authorization need both an injection/user surface AND,
        # ideally, an authenticated session. The score reflects that.
        for injection in injection_nodes or [{"id": "recon"}]:
            for user in user_nodes:
                self.add_hypothesis(
                    source=injection["id"],
                    target="idor_check",
                    reason="User-owned resources present; test for IDOR.",
                    score=0.0,
                )
                break  # one idor hypothesis is enough

        for user in user_nodes:
            self.add_hypothesis(
                source=user["id"],
                target="authorization",
                reason="User/privileged endpoint discovered.",
                score=0.0,
            )

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------
    def calculate_score(self, hypothesis, state):
        """
        Evidence- and session-aware score in [0, 1].

        Base priors give a sensible static order (discovery first), and
        runtime evidence (a discovered surface, an authenticated session, a
        confirmed vulnerability) raises the follow-up modules so the
        orchestrator is guided dynamically rather than by a flat 0.5.
        """
        target = hypothesis["target"]
        executed = state.get("modules_run", [])
        session = self._has_session(state)

        base = {
            "sqli_check": 0.60,
            "xss_check": 0.55,
            "auth": 0.50,
            "authorization": 0.35,
            "idor_check": 0.30,
        }.get(target, 0.0)

        score = base

        if target == "sqli_check":
            if self._has(INJECTION_TYPES):
                score += 0.30

        elif target == "xss_check":
            if self._has(CLIENT_TYPES):
                score += 0.25

        elif target == "auth":
            if self._has(AUTH_TYPES):
                score += 0.15
            # Obtaining a session is valuable only while we have none.
            if not session:
                score += 0.20
            else:
                score -= 0.10

        elif target == "idor_check":
            # Only worth running once an authenticated session exists.
            if session:
                score += 0.55
            if self._has(USER_RESOURCE_TYPES):
                score += 0.10
            if session and self._module_vulnerable(state, "sqli"):
                score += 0.10

        elif target == "authorization":
            if session:
                score += 0.40
            if self._has(USER_RESOURCE_TYPES):
                score += 0.15

        # Never re-run a module that already ran.
        if target in executed:
            score -= 1.0

        return round(max(0.0, min(score, 1.0)), 2)

    def validate_hypotheses(self, state):
        for hypothesis in self.hypotheses:
            hypothesis["score"] = self.calculate_score(hypothesis, state)
            hypothesis["validated"] = hypothesis["score"] > 0.0
        return self.get_candidates()

    # ------------------------------------------------------------------
    # Chains
    # ------------------------------------------------------------------
    def score_chain(self, chain, state):
        executed = state.get("modules_run", [])
        session = self._has_session(state)
        sqli_vuln = self._module_vulnerable(state, "sqli")
        xss_vuln = self._module_vulnerable(state, "xss")

        score = 0.0
        for action in chain:
            if action in executed:
                score -= 0.5
                continue

            if action == "sqli_check":
                score += 0.60
                if self._has(INJECTION_TYPES):
                    score += 0.30
            elif action == "xss_check":
                score += 0.55
                if self._has(CLIENT_TYPES):
                    score += 0.25
                if xss_vuln:
                    score += 0.10
            elif action == "auth":
                score += 0.50
                if self._has(AUTH_TYPES):
                    score += 0.15
                if not session:
                    score += 0.20
            elif action == "idor_check":
                if session:
                    score += 0.70
                if sqli_vuln and session:
                    score += 0.20
            elif action == "authorization":
                score += 0.35
                if session:
                    score += 0.40
                if self._has(USER_RESOURCE_TYPES):
                    score += 0.15

        return round(max(0.0, min(score, 1.0)), 2)

    def rank_chains(self, chains, state):
        ranked = [
            {"chain": chain, "score": self.score_chain(chain, state)}
            for chain in chains
        ]
        return sorted(ranked, key=lambda x: x["score"], reverse=True)

    def generate_chains(self, state):
        """
        Produce candidate chains, highest-scoring hypotheses first. Each
        viable module becomes a chain; a confirmed/likely SQLi additionally
        seeds the sqli -> idor multi-step chain.
        """
        executed = state.get("modules_run", [])
        candidates = self.validate_hypotheses(state)

        chains = []
        seen = set()

        def _add(chain):
            key = tuple(chain)
            if key not in seen:
                seen.add(key)
                chains.append(chain)

        for candidate in candidates:
            target = candidate.get("target")
            if not target or target in executed or candidate["score"] <= 0.0:
                continue

            if target == "sqli_check":
                # Seed the multi-step chain only if idor has not yet run.
                if "idor_check" not in executed:
                    _add(["sqli_check", "idor_check"])
                else:
                    _add(["sqli_check"])
            else:
                _add([target])

        return chains
