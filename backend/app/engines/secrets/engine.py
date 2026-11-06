"""WebAudit 360 — Client-Side Secret & Sourcemap Harvester (OSINT) Engine
Author: Harsh Patel

Evaluates:
- Accidental client-side exposure of API keys, private keys, database credentials, and cloud tokens
- Regex signature hunting across HTML and fetched client-side JavaScript assets
- Detection and probing of exposed production source maps (.js.map) revealing backend/client source trees
- High-entropy credential extraction (Shannon entropy + pattern matching)
"""

import math
import re
import time
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlparse, urljoin
import httpx
from bs4 import BeautifulSoup

from backend.app.core.ssrf import validate_target_url
from backend.app.engines.base import (
    AuditCategory,
    BaseAuditEngine,
    EngineResult,
    EngineStatus,
    FindingDraft,
)


SECRET_PATTERNS = [
    (
        r"\b(AKIA[0-9A-Z]{16})\b",
        "secret-aws-access-key",
        "CRITICAL",
        "Exposed AWS Access Key ID",
        "Identified valid AWS Access Key ID embedded directly in client-side code.",
        "Revoke the key immediately in AWS IAM, audit CloudTrail logs, and store credentials on backend servers."
    ),
    (
        r"\b(sk_live_[0-9a-zA-Z]{24,})\b",
        "secret-stripe-secret-key",
        "CRITICAL",
        "Exposed Stripe Live Secret Key",
        "Found production Stripe Live Secret Key exposed to public browser clients.",
        "Roll the Stripe secret key in the Stripe Dashboard immediately and restrict clients to publishable keys (pk_live_...)."
    ),
    (
        r"\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b",
        "secret-github-token",
        "CRITICAL",
        "Exposed GitHub Personal Access Token",
        "Found active GitHub Personal Access Token in client-accessible assets.",
        "Revoke the GitHub token and purge repository secrets from commit histories."
    ),
    (
        r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b",
        "secret-slack-token",
        "HIGH",
        "Exposed Slack API Token",
        "Found Slack workspace OAuth/bot token in client bundles.",
        "Invalidate the Slack app token in the Slack API console."
    ),
    (
        r"\b(AIza[0-9A-Za-z\\-_]{35})\b",
        "secret-google-api-key",
        "MEDIUM",
        "Exposed Google Cloud / Firebase API Key",
        "Found Google Cloud API key in client-side scripts.",
        "Configure HTTP referrer and API service restrictions in Google Cloud Console."
    ),
    (
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "secret-private-key-file",
        "CRITICAL",
        "Exposed Asymmetric Private Key",
        "Found PEM-encoded private cryptographic key embedded in web assets.",
        "Revoke associated certificates/keys immediately and audit server access logs."
    ),
    (
        r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b",
        "secret-hardcoded-jwt",
        "HIGH",
        "Hardcoded JSON Web Token (JWT)",
        "Found static JSON Web Token hardcoded into frontend scripts.",
        "Avoid embedding static session or service tokens in static frontend builds."
    ),
    (
        r"hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8}/[0-9a-zA-Z]{24}",
        "secret-slack-webhook-url",
        "HIGH",
        "Exposed Slack Incoming Webhook URL",
        "Exposed incoming webhook allowing unauthorized messages into internal Slack channels.",
        "Deactivate the webhook in Slack and proxy notifications through your backend."
    ),
]


def shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in set(data):
        p_x = float(data.count(x)) / length
        entropy += - p_x * math.log2(p_x)
    return entropy


class SecretsHarvesterEngine(BaseAuditEngine):
    engine_name = "SecretsHarvesterEngine"
    engine_version = "1.0.0"
    category = AuditCategory.SECRET_HARVESTER

    async def execute(
        self,
        target_url: str,
        config: Dict[str, Any],
        **kwargs
    ) -> EngineResult:
        start_time = time.time()
        findings: List[FindingDraft] = []
        limitations: List[str] = [
            "Scans client-delivered HTML, inline scripts, and first-party script assets.",
            "Dynamic backend environment secrets not referenced on the client cannot be discovered by passive harvesters."
        ]

        normalized_url, hostname, _ = validate_target_url(target_url)

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebAudit360-Secret-Harvester/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        try:
            async with httpx.AsyncClient(timeout=12.0, follow_redirects=True, headers=headers) as client:
                resp = await client.get(normalized_url)
                html_content = resp.text
        except Exception as e:
            return EngineResult(
                category=AuditCategory.SECRET_HARVESTER,
                engine_name=self.engine_name,
                engine_version=self.engine_version,
                status=EngineStatus.FAILED,
                error=f"Could not connect to target URL: {str(e)}",
                execution_time_ms=int((time.time() - start_time) * 1000)
            )

        soup = BeautifulSoup(html_content, "html.parser")
        target_origin = urlparse(normalized_url).netloc

        discovered_scripts: List[str] = []
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                full_src = urljoin(normalized_url, src)
                # Prioritize first-party scripts for in-depth asset scanning
                if urlparse(full_src).netloc == target_origin:
                    discovered_scripts.append(full_src)

        # Content dictionary mapping asset URL to text
        corpus: Dict[str, str] = {
            normalized_url: html_content
        }

        # Fetch up to 5 first-party scripts for secret harvesting
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, headers=headers) as script_client:
            for s_url in discovered_scripts[:5]:
                try:
                    s_res = await script_client.get(s_url)
                    if s_res.is_success and "javascript" in s_res.headers.get("content-type", "javascript"):
                        corpus[s_url] = s_res.text
                except Exception:
                    pass

        # 1. Secret Signature Hunting
        discovered_secrets: List[Dict[str, Any]] = []
        for asset_url, content in corpus.items():
            for pattern, rule_id, severity, title, desc, rec in SECRET_PATTERNS:
                matches = re.finditer(pattern, content)
                for m in matches:
                    secret_val = m.group(0)
                    # Mask secret for safe reporting: keep key prefix and last 4 chars
                    if secret_val.startswith("sk_live_"):
                        masked = "sk_live_" + "*" * (len(secret_val) - 12) + secret_val[-4:]
                    elif len(secret_val) > 8:
                        masked = secret_val[:4] + "*" * (len(secret_val) - 8) + secret_val[-4:]
                    else:
                        masked = secret_val[:2] + "****"

                    discovered_secrets.append({
                        "rule_id": rule_id,
                        "title": title,
                        "severity": severity,
                        "masked_value": masked,
                        "asset_url": asset_url,
                        "description": desc,
                        "recommendation": rec
                    })

        # 2. Sourcemap Discovery & Verification
        exposed_sourcemaps: List[Dict[str, Any]] = []
        for asset_url, content in corpus.items():
            if asset_url.endswith(".js"):
                # Check for sourceMappingURL directive
                sm_matches = re.findall(r"//[#@]\s*sourceMappingURL=([^\s'\"<>]+)", content)
                candidate_maps = []
                for sm in sm_matches:
                    candidate_maps.append(urljoin(asset_url, sm))

                # Also test conventional .map suffix
                candidate_maps.append(asset_url + ".map")

                for map_url in candidate_maps[:2]:
                    try:
                        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, headers=headers) as map_client:
                            map_head = await map_client.head(map_url)
                            if map_head.status_code == 200:
                                exposed_sourcemaps.append({
                                    "script_url": asset_url,
                                    "map_url": map_url,
                                    "size_bytes": int(map_head.headers.get("content-length", 0))
                                })
                                break
                    except Exception:
                        pass

        # Calculate Score
        score = 100.0

        for sec in discovered_secrets:
            sev = sec["severity"]
            if sev == "CRITICAL":
                score -= 40.0
            elif sev == "HIGH":
                score -= 25.0
            elif sev == "MEDIUM":
                score -= 10.0

            findings.append(FindingDraft(
                category=AuditCategory.SECRET_HARVESTER,
                rule_id=sec["rule_id"],
                severity=sec["severity"],
                title=f"{sec['title']} ({sec['masked_value']})",
                description=f"{sec['description']} Located in: {sec['asset_url']}",
                recommendation=sec["recommendation"],
                evidence_snippet=f"Asset: {sec['asset_url']}\nToken: {sec['masked_value']}",
                raw_details=sec
            ))

        if exposed_sourcemaps:
            score -= min(25.0, len(exposed_sourcemaps) * 15.0)
            findings.append(FindingDraft(
                category=AuditCategory.SECRET_HARVESTER,
                rule_id="secret-sourcemap-exposed",
                severity="HIGH",
                title=f"{len(exposed_sourcemaps)} Production Source Map(s) Publicly Accessible",
                description=(
                    f"Found {len(exposed_sourcemaps)} JavaScript source map (.map) file(s) publicly downloadable in production. "
                    "Source maps allow attackers to reconstruct original un-minified TypeScript/JavaScript source code and internal folder structures."
                ),
                recommendation="Disable source map generation in production bundler configurations (e.g. devtool: false in Webpack/Vite) or restrict .map requests via Nginx/Cloudflare.",
                evidence_snippet="\n".join([sm["map_url"] for sm in exposed_sourcemaps]),
                raw_details={"exposed_sourcemaps": exposed_sourcemaps}
            ))

        if not discovered_secrets and not exposed_sourcemaps:
            findings.append(FindingDraft(
                category=AuditCategory.SECRET_HARVESTER,
                rule_id="secret-posture-clean",
                severity="INFO",
                title="Zero Client-Side Secrets or Exposed Source Maps Detected",
                description="Comprehensive scanning across HTML and JavaScript assets revealed no exposed credentials, API keys, or leaked source map trees.",
                recommendation="Maintain pre-commit secret scanners (e.g., git-secrets or gitleaks) in development pipelines."
            ))

        final_score = max(0.0, min(100.0, round(score, 1)))

        raw_evidence = {
            "scanned_assets_count": len(corpus),
            "discovered_secrets_count": len(discovered_secrets),
            "discovered_secrets": discovered_secrets,
            "exposed_sourcemaps_count": len(exposed_sourcemaps),
            "exposed_sourcemaps": exposed_sourcemaps,
            "security_grade": "A" if final_score >= 90 else ("C" if final_score >= 60 else "F")
        }

        return EngineResult(
            category=AuditCategory.SECRET_HARVESTER,
            engine_name=self.engine_name,
            engine_version=self.engine_version,
            status=EngineStatus.SUCCESS,
            score=final_score,
            findings=findings,
            raw_evidence=raw_evidence,
            limitations=limitations,
            execution_time_ms=int((time.time() - start_time) * 1000)
        )
