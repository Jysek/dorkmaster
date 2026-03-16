"""
DorkForge - Core Dork Generation Engine
========================================

Pure-logic engine with ZERO UI dependencies.
Generates syntactically correct dork queries for multiple search engines
using operators and keywords loaded from configuration.

Classes:
    DorkConfig      - Loads and manages search engine configuration
    DorkBuilder     - Builds syntactically correct operator:value terms
    DorkValidator   - Validates dorks against generation rules
    DorkGenerator   - Main generation engine combining all components

Quoting Rules for Search Engine Dorks:
    - site:         NEVER quoted  (site:example.com)
    - filetype/ext: NEVER quoted  (filetype:pdf)
    - intitle:      Quoted when value contains spaces (intitle:"admin panel")
    - inurl:        Quoted when value contains spaces (inurl:"admin/login")
    - intext:       Quoted when value contains spaces (intext:"error log")
    - allintitle:   NEVER quoted  (allintitle: admin panel login)
    - allinurl:     NEVER quoted  (allinurl: admin login page)
    - allintext:    NEVER quoted  (allintext: admin panel login)
"""

import json
import os
import random
import itertools
from typing import List, Dict, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Operator quoting categories
# ---------------------------------------------------------------------------

# Values must NEVER be quoted (single-token or domain values)
_NEVER_QUOTE_OPS = frozenset({
    "site", "filetype", "ext", "cache", "related", "info",
    "ip", "language", "location", "hostname", "feed", "hasfeed",
    "mime", "host", "rhost", "domain", "date", "lang", "cat",
    "port", "os", "city", "country", "org", "isp", "net",
    "product", "version", "http.status", "ssl.cert.expired",
    "has_screenshot", "vuln", "tag", "asn", "http.favicon.hash",
    "before", "after", "numrange",
    "user", "repo", "extension", "path", "size",
    "stars", "forks", "created", "pushed",
    "source", "loc", "weather", "stocks", "map",
    "url", "near", "linkfromdomain",
})

# Operators that accept space-separated word lists (NOT quoted as a phrase)
_MULTI_WORD_OPS = frozenset({
    "allintitle", "allinurl", "allintext", "allinanchor",
})

# Operators whose values should be quoted when they contain spaces
_QUOTE_ON_SPACE_OPS = frozenset({
    "intitle", "inurl", "intext", "inbody", "inanchor",
    "define", "contains", "prefer",
    "http.title", "http.html", "http.component",
    "ssl", "ssl.cert.subject.cn", "ssl.cert.issuer.cn",
    "in:name", "in:description", "in:readme", "in:file", "in:path",
    "filename", "link",
})

# Maximum absolute cap to prevent runaway memory (safety valve)
_ABSOLUTE_MAX_DORKS = 500_000


# ----------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------

class DorkConfig:
    """Loads and manages configuration for search engines, operators, and filetypes.

    Implements singleton pattern for shared configuration access.
    """

    _instance: Optional["DorkConfig"] = None

    @classmethod
    def get_instance(cls) -> "DorkConfig":
        """Return the shared configuration singleton."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset singleton (useful for testing)."""
        cls._instance = None

    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            project_root = os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))
            )
            config_path = os.path.join(project_root, "config", "default_config.json")

        with open(config_path, "r", encoding="utf-8") as f:
            self._config: Dict = json.load(f)

    @property
    def search_engines(self) -> Dict:
        return self._config.get("search_engines", {})

    @property
    def default_keywords(self) -> Dict[str, List[str]]:
        return self._config.get("default_keywords", {})

    @property
    def generation_rules(self) -> Dict:
        return self._config.get("generation_rules", {})

    def get_engine(self, engine_id: str) -> Optional[Dict]:
        """Get full engine configuration dict, or None if not found."""
        return self.search_engines.get(engine_id)

    def get_operators(self, engine_id: str) -> Dict:
        """Get operators dict for a specific engine."""
        engine = self.get_engine(engine_id)
        return engine.get("operators", {}) if engine else {}

    def get_filetypes(self, engine_id: str) -> List[str]:
        """Get filetype list for a specific engine."""
        engine = self.get_engine(engine_id)
        return engine.get("filetype_list", []) if engine else []

    def get_boolean_ops(self, engine_id: str) -> Dict:
        """Get boolean operators dict for a specific engine."""
        engine = self.get_engine(engine_id)
        return engine.get("boolean_operators", {}) if engine else {}

    def get_all_engine_ids(self) -> List[str]:
        """Return list of all configured engine IDs."""
        return list(self.search_engines.keys())

    def get_engine_display_name(self, engine_id: str) -> str:
        """Return display name for an engine (falls back to engine_id)."""
        engine = self.get_engine(engine_id)
        return engine.get("name", engine_id) if engine else engine_id


# ----------------------------------------------------------------
# Builder
# ----------------------------------------------------------------

class DorkBuilder:
    """Builds syntactically correct dork queries for a specific search engine.

    Handles operator formatting, quoting, boolean joining, and negation
    according to each engine's specific syntax rules.
    """

    def __init__(self, config: DorkConfig, engine_id: str = "google"):
        self.config = config
        self.engine_id = engine_id
        self.engine = config.get_engine(engine_id) or {}
        self.operators = self.engine.get("operators", {})
        self.boolean_ops = self.engine.get("boolean_operators", {})

    def build_operator_term(self, operator_key: str, value: str) -> str:
        """Build a single operator:value term with correct syntax and quoting.

        Quoting rules:
          - _NEVER_QUOTE_OPS: NEVER quote the value
          - _MULTI_WORD_OPS: NEVER quote (space-separated lists)
          - _QUOTE_ON_SPACE_OPS: Quote when value has spaces
          - Unknown operators: return value as-is
        """
        op_def = self.operators.get(operator_key)
        if op_def is None:
            return value

        op_lower = operator_key.lower()

        # Determine if value needs quoting
        needs_quoting = False
        if op_lower in _QUOTE_ON_SPACE_OPS and " " in value.strip():
            stripped = value.strip()
            if not (stripped.startswith('"') and stripped.endswith('"')):
                needs_quoting = True

        if needs_quoting:
            quoted_value = f'"{value}"'
            return op_def["syntax"].replace("{value}", quoted_value)

        return op_def["syntax"].replace("{value}", value)

    def quote_value(self, value: str) -> str:
        """Wrap value in quotes using the engine's exact-match syntax."""
        exact_syntax = self.boolean_ops.get("EXACT", '"{value}"')
        if exact_syntax is None:
            return value
        return exact_syntax.replace("{value}", value)

    def join_terms(self, terms: List[str], operator: str = "AND") -> str:
        """Join multiple dork terms with the correct boolean connector."""
        joiner = self.boolean_ops.get(operator, " ")
        if joiner is None:
            joiner = " "
        return joiner.join(terms)

    def negate_term(self, term: str) -> str:
        """Negate a term using the engine's NOT syntax."""
        not_syntax = self.boolean_ops.get("NOT", " -")
        if not_syntax is None:
            return f"-{term}"

        stripped = not_syntax.strip()
        if stripped and stripped[-1].isalpha():
            return f"{stripped} {term}"
        else:
            return f"{stripped}{term}"


# ----------------------------------------------------------------
# Validator
# ----------------------------------------------------------------

class DorkValidator:
    """Validates generated dorks against configuration rules.

    Rules enforced:
    - Maximum dork string length
    - Maximum number of operators per dork
    - Mutually exclusive operator pairs (e.g., filetype + ext)
    - No duplicate non-site operators
    """

    def __init__(self, config: DorkConfig):
        self.config = config
        rules = config.generation_rules
        self._mutually_exclusive: List[Set[str]] = [
            set(group) for group in rules.get("mutually_exclusive", [])
        ]
        self._max_ops: int = rules.get("max_operators_per_dork", 5)
        self._max_len: int = rules.get("max_dork_length", 512)

    def is_valid(self, dork: str, engine_id: str) -> bool:
        """Check if a dork string passes all validation rules."""
        if not dork or not dork.strip():
            return False

        if len(dork) > self._max_len:
            return False

        operators_found = self._extract_operators(dork, engine_id)

        if len(operators_found) > self._max_ops:
            return False

        # Check mutually exclusive operators
        for exclusive_group in self._mutually_exclusive:
            found_in_group = [op for op in operators_found if op in exclusive_group]
            if len(set(found_in_group)) > 1:
                return False

        # Check duplicate non-site operators
        op_counts: Dict[str, int] = {}
        for op in operators_found:
            op_counts[op] = op_counts.get(op, 0) + 1
        for op, count in op_counts.items():
            if count > 1 and op != "site":
                return False

        return True

    def _extract_operators(self, dork: str, engine_id: str) -> List[str]:
        """Extract operator names present in a dork string.

        Handles compound operators (e.g. http.title, ssl.cert.subject.cn)
        by checking longest match first.
        """
        engine_ops = self.config.get_operators(engine_id)
        # Sort by length descending so compound operators are matched first
        sorted_ops = sorted(engine_ops.keys(), key=len, reverse=True)
        operators_found: List[str] = []

        tokens = self._tokenize(dork)
        for token in tokens:
            clean = token.lower().lstrip("-(").rstrip(")")
            if ":" not in clean:
                continue

            matched = False
            for op_key in sorted_ops:
                if clean.startswith(op_key.lower() + ":"):
                    operators_found.append(op_key)
                    matched = True
                    break

            if not matched:
                # Fallback: simple prefix extraction
                prefix = clean.split(":")[0]
                if prefix in engine_ops:
                    operators_found.append(prefix)

        return operators_found

    @staticmethod
    def _tokenize(dork: str) -> List[str]:
        """Split dork into tokens respecting quoted strings."""
        tokens: List[str] = []
        current = ""
        in_quotes = False

        for ch in dork:
            if ch == '"':
                in_quotes = not in_quotes
                current += ch
            elif ch == " " and not in_quotes:
                if current:
                    tokens.append(current)
                    current = ""
            else:
                current += ch

        if current:
            tokens.append(current)

        return tokens


# ----------------------------------------------------------------
# Generator
# ----------------------------------------------------------------

class DorkGenerator:
    """Main dork generation engine.

    Generates valid, deduplicated dork queries by combining operators,
    keywords, and filetypes according to correct syntax per search engine.

    Supports:
    - max_results=0 means generate ALL possible combinations (no limit)
    - max_results>0 means cap at that number
    - Multi-operator combinations (pairs of operators per dork)
    - Single-operator + keyword + filetype combos
    - Bare keyword + filetype combos
    - Bare keyword combos
    """

    def __init__(self, config: Optional[DorkConfig] = None):
        self.config = config or DorkConfig.get_instance()
        self.validator = DorkValidator(self.config)

    def count_combinations(
        self,
        engine_id: str,
        keywords: List[str],
        selected_operators: Optional[List[str]] = None,
        selected_filetypes: Optional[List[str]] = None,
        custom_site: Optional[str] = None,
        include_exclusions: Optional[List[str]] = None,
    ) -> int:
        """Estimate total possible unique combinations without generating them.

        Used by the UI to show the user how many dorks are possible.
        """
        available_ops = self.config.get_operators(engine_id)

        if not keywords:
            return 0

        # Filter valid inputs
        valid_ops = [op for op in (selected_operators or []) if op in available_ops]
        available_ft = self.config.get_filetypes(engine_id)
        valid_ft = [ft for ft in (selected_filetypes or []) if ft in available_ft]

        kw_count = len(keywords)
        non_ft_ops = [op for op in valid_ops if op not in ("filetype", "ext", "mime")]
        op_count = len(non_ft_ops)
        ft_count = len(valid_ft)

        total = 0

        if op_count > 0 and ft_count > 0:
            # Single operator + keyword + filetype
            total += op_count * kw_count * ft_count
            # Bare keyword + filetype
            total += kw_count * ft_count
            # Multi-operator pairs + keyword (no filetype)
            if op_count >= 2:
                pair_count = op_count * (op_count - 1) // 2
                total += pair_count * kw_count
            # Multi-operator pairs + keyword + filetype
            if op_count >= 2:
                pair_count = op_count * (op_count - 1) // 2
                total += pair_count * kw_count * ft_count
        elif op_count > 0:
            # Single operator + keyword
            total += op_count * kw_count
            # Multi-operator pairs + keyword
            if op_count >= 2:
                pair_count = op_count * (op_count - 1) // 2
                total += pair_count * kw_count
        elif ft_count > 0:
            # Bare keyword + filetype
            total += kw_count * ft_count
        else:
            # Bare keywords only
            total += kw_count

        return total

    def generate(
        self,
        engine_id: str,
        keywords: List[str],
        selected_operators: Optional[List[str]] = None,
        selected_filetypes: Optional[List[str]] = None,
        custom_site: Optional[str] = None,
        use_quotes: bool = False,
        include_exclusions: Optional[List[str]] = None,
        max_results: int = 100,
        shuffle: bool = True,
    ) -> Dict:
        """Generate dork queries.

        Args:
            engine_id:          Search engine key.
            keywords:           List of target keywords/phrases.
            selected_operators: Operator keys to use.
            selected_filetypes: File extensions to target.
            custom_site:        Optional site: domain restriction.
            use_quotes:         Wrap bare keywords in exact-match quotes.
            include_exclusions: Terms to negate.
            max_results:        Max dorks to return. 0 = generate ALL.
            shuffle:            Randomize output order.

        Returns:
            Dict with keys: dorks, total_generated, total_possible,
            engine, engine_name, warnings.
        """
        builder = DorkBuilder(self.config, engine_id)
        available_ops = self.config.get_operators(engine_id)
        warnings: List[str] = []

        # -- Validate keywords --
        if not keywords:
            return self._empty_result(engine_id, ["No keywords provided."])

        # -- Validate selected operators --
        if selected_operators:
            valid_ops = [op for op in selected_operators if op in available_ops]
            invalid_ops = [op for op in selected_operators if op not in available_ops]
            if invalid_ops:
                warnings.append(
                    f"Operators not available for {engine_id}: {', '.join(invalid_ops)}"
                )
            selected_operators = valid_ops
        else:
            selected_operators = []

        # -- Validate filetypes --
        available_filetypes = self.config.get_filetypes(engine_id)
        if selected_filetypes:
            valid_ft = [ft for ft in selected_filetypes if ft in available_filetypes]
            invalid_ft = [ft for ft in selected_filetypes if ft not in available_filetypes]
            if invalid_ft:
                warnings.append(
                    f"Filetypes not available for {engine_id}: {', '.join(invalid_ft)}"
                )
            selected_filetypes = valid_ft
        else:
            selected_filetypes = []

        # -- Determine filetype operator key --
        filetype_op_key = self._get_filetype_op_key(engine_id, available_ops)
        if selected_filetypes and filetype_op_key is None:
            warnings.append(f"Filetype operator not available for {engine_id}.")
            selected_filetypes = []

        # -- Process keywords --
        processed_keywords = [kw.strip() for kw in keywords if kw.strip()]
        if not processed_keywords:
            return self._empty_result(engine_id, ["No valid keywords after processing."])

        # -- Build exclusion suffix --
        exclusion_parts: List[str] = []
        if include_exclusions:
            for exc in include_exclusions:
                exc = exc.strip()
                if exc:
                    exclusion_parts.append(builder.negate_term(exc))
        exclusion_suffix = " ".join(exclusion_parts)

        # -- Build site prefix --
        site_prefix = ""
        if custom_site and custom_site.strip():
            site_op = available_ops.get("site")
            if site_op:
                site_prefix = builder.build_operator_term("site", custom_site.strip())

        # -- Filter non-filetype operators --
        non_ft_ops = [
            op for op in selected_operators
            if op not in ("filetype", "ext", "mime")
        ]

        # -- Generate all combinations --
        all_dorks: List[str] = []

        # Strategy 1: Single operator + keyword [+ filetype] [+ site] [+ exclusions]
        if non_ft_ops and selected_filetypes:
            for op_key, kw, ft in itertools.product(
                non_ft_ops, processed_keywords, selected_filetypes
            ):
                dork = self._assemble_dork(
                    builder, [
                        builder.build_operator_term(op_key, kw),
                        builder.build_operator_term(filetype_op_key, ft),
                    ],
                    site_prefix, exclusion_suffix,
                )
                all_dorks.append(dork)

            # Also: bare keyword + filetype
            for kw, ft in itertools.product(processed_keywords, selected_filetypes):
                bare_kw = builder.quote_value(kw) if use_quotes else kw
                dork = self._assemble_dork(
                    builder, [
                        bare_kw,
                        builder.build_operator_term(filetype_op_key, ft),
                    ],
                    site_prefix, exclusion_suffix,
                )
                all_dorks.append(dork)

        elif non_ft_ops:
            # Single operator + keyword
            for op_key, kw in itertools.product(non_ft_ops, processed_keywords):
                dork = self._assemble_dork(
                    builder, [builder.build_operator_term(op_key, kw)],
                    site_prefix, exclusion_suffix,
                )
                all_dorks.append(dork)

        elif selected_filetypes:
            # Bare keyword + filetype
            for kw, ft in itertools.product(processed_keywords, selected_filetypes):
                bare_kw = builder.quote_value(kw) if use_quotes else kw
                dork = self._assemble_dork(
                    builder, [
                        bare_kw,
                        builder.build_operator_term(filetype_op_key, ft),
                    ],
                    site_prefix, exclusion_suffix,
                )
                all_dorks.append(dork)

        else:
            # Bare keywords only
            for kw in processed_keywords:
                bare_kw = builder.quote_value(kw) if use_quotes else kw
                dork = self._assemble_dork(
                    builder, [bare_kw], site_prefix, exclusion_suffix,
                )
                all_dorks.append(dork)

        # Strategy 2: Multi-operator pairs (2 different operators + keyword)
        if len(non_ft_ops) >= 2:
            op_pairs = list(itertools.combinations(non_ft_ops, 2))

            if selected_filetypes:
                # Pair + keyword + filetype
                for (op_a, op_b), kw, ft in itertools.product(
                    op_pairs, processed_keywords, selected_filetypes
                ):
                    dork = self._assemble_dork(
                        builder, [
                            builder.build_operator_term(op_a, kw),
                            builder.build_operator_term(op_b, kw),
                            builder.build_operator_term(filetype_op_key, ft),
                        ],
                        site_prefix, exclusion_suffix,
                    )
                    all_dorks.append(dork)

            # Pair + keyword (no filetype)
            for (op_a, op_b), kw in itertools.product(op_pairs, processed_keywords):
                dork = self._assemble_dork(
                    builder, [
                        builder.build_operator_term(op_a, kw),
                        builder.build_operator_term(op_b, kw),
                    ],
                    site_prefix, exclusion_suffix,
                )
                all_dorks.append(dork)

        # -- Deduplicate --
        seen: Set[str] = set()
        unique_dorks: List[str] = []
        for d in all_dorks:
            d_clean = d.strip()
            if d_clean and d_clean not in seen:
                seen.add(d_clean)
                unique_dorks.append(d_clean)

        total_possible = len(unique_dorks)

        # -- Validate --
        valid_dorks: List[str] = []
        invalid_count = 0
        for d in unique_dorks:
            if self.validator.is_valid(d, engine_id):
                valid_dorks.append(d)
            else:
                invalid_count += 1

        if invalid_count > 0:
            warnings.append(f"Filtered {invalid_count} invalid combinations.")

        # -- Shuffle --
        if shuffle:
            random.shuffle(valid_dorks)

        # -- Apply limit --
        # max_results == 0 means "generate all" (no limit except safety cap)
        if max_results <= 0:
            effective_limit = _ABSOLUTE_MAX_DORKS
        else:
            effective_limit = min(max_results, _ABSOLUTE_MAX_DORKS)

        result_dorks = valid_dorks[:effective_limit]

        if len(valid_dorks) > effective_limit:
            warnings.append(
                f"Capped output at {effective_limit:,} (total valid: {len(valid_dorks):,})."
            )

        return {
            "dorks": result_dorks,
            "total_generated": len(result_dorks),
            "total_possible": total_possible,
            "engine": engine_id,
            "engine_name": self.config.get_engine_display_name(engine_id),
            "warnings": warnings,
        }

    # -- Helpers --

    def _assemble_dork(
        self,
        builder: DorkBuilder,
        parts: List[str],
        site_prefix: str,
        exclusion_suffix: str,
    ) -> str:
        """Assemble a complete dork from parts, site, and exclusions."""
        if site_prefix:
            parts.append(site_prefix)
        dork = builder.join_terms(parts)
        if exclusion_suffix:
            dork = f"{dork} {exclusion_suffix}"
        return dork

    @staticmethod
    def _get_filetype_op_key(engine_id: str, available_ops: Dict) -> Optional[str]:
        """Determine the correct filetype operator for the engine."""
        if "filetype" in available_ops:
            return "filetype"
        if "ext" in available_ops:
            return "ext"
        if "mime" in available_ops:
            return "mime"
        return None

    def _empty_result(self, engine_id: str, warnings: List[str]) -> Dict:
        """Return a standardized empty result."""
        return {
            "dorks": [],
            "total_generated": 0,
            "total_possible": 0,
            "engine": engine_id,
            "engine_name": self.config.get_engine_display_name(engine_id),
            "warnings": warnings,
        }
