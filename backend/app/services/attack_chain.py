from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.vulnerability import Vulnerability


@dataclass
class AttackChainStep:
    vuln_id: str
    title: str
    severity: str
    chain_position: int
    verification_status: str
    mitre_techniques: List[str]
    exploit_available: bool
    cvss_score: Optional[float]


@dataclass
class AttackChain:
    chain_id: str
    steps: List[AttackChainStep] = field(default_factory=list)
    entry_point: str = ""
    final_impact: str = ""
    max_severity: str = "info"
    total_steps: int = 0
    fully_exploitable: bool = False
    all_mitre_techniques: List[str] = field(default_factory=list)


_SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _max_severity(steps: List[AttackChainStep]) -> str:
    if not steps:
        return "info"
    return max(steps, key=lambda s: _SEVERITY_ORDER.get(s.severity.lower(), 0)).severity.lower()


class AttackChainService:
    async def get_chains(self, session_id: str, db: AsyncSession) -> List[Dict]:
        import uuid as _uuid
        result = await db.execute(
            select(Vulnerability).where(
                Vulnerability.session_id == _uuid.UUID(session_id)
            )
        )
        vulns = result.scalars().all()

        chains: Dict[str, AttackChain] = {}

        # Group explicitly-chained vulns
        for v in vulns:
            if not v.attack_chain_id:
                continue
            cid = v.attack_chain_id
            if cid not in chains:
                chains[cid] = AttackChain(chain_id=cid)

            chains[cid].steps.append(
                AttackChainStep(
                    vuln_id=str(v.id),
                    title=v.title,
                    severity=v.severity.lower(),
                    chain_position=v.chain_position or 0,
                    verification_status=v.verification_status,
                    mitre_techniques=v.mitre_techniques or [],
                    exploit_available=v.exploit_available,
                    cvss_score=v.cvss_score,
                )
            )

        # Infer chains from unlinked vulns sharing the same port/service
        unchained = [v for v in vulns if not v.attack_chain_id]
        inferred: Dict[str, List[Vulnerability]] = {}
        for v in unchained:
            key = f"{v.port or 0}-{v.affected_service or 'unknown'}"
            inferred.setdefault(key, []).append(v)

        for key, group in inferred.items():
            if len(group) >= 2:
                # Multi-vuln bucket → a real inferred chain with a shared id
                # derived from the (port, service) tuple they share.
                cid = f"inferred-{key}"
            else:
                # Singleton. Used to be silently dropped, which meant one-off
                # findings never showed up on the Chains tab. Render it as a
                # 1-step chain with a chain_id unique to the finding so two
                # unrelated singletons can't collide on (port, service) keys.
                only = group[0]
                cid = f"inferred-single-{str(only.id)[:8]}"
            if cid not in chains:
                chains[cid] = AttackChain(chain_id=cid)
            for pos, v in enumerate(
                sorted(group, key=lambda x: _SEVERITY_ORDER.get(x.severity.lower(), 0))
            ):
                chains[cid].steps.append(
                    AttackChainStep(
                        vuln_id=str(v.id),
                        title=v.title,
                        severity=v.severity.lower(),
                        chain_position=pos + 1,
                        verification_status=v.verification_status,
                        mitre_techniques=v.mitre_techniques or [],
                        exploit_available=v.exploit_available,
                        cvss_score=v.cvss_score,
                    )
                )

        # Finalize each chain
        output = []
        for chain in chains.values():
            chain.steps.sort(key=lambda s: s.chain_position)
            chain.total_steps = len(chain.steps)
            chain.entry_point = chain.steps[0].title if chain.steps else ""
            chain.final_impact = _max_severity_step(chain.steps)
            chain.max_severity = _max_severity(chain.steps)
            chain.fully_exploitable = all(
                s.verification_status in ("confirmed", "exploited") for s in chain.steps
            )
            chain.all_mitre_techniques = list({
                t for s in chain.steps for t in s.mitre_techniques
            })

            output.append({
                "chain_id": chain.chain_id,
                "entry_point": chain.entry_point,
                "final_impact": chain.final_impact,
                "max_severity": chain.max_severity,
                "total_steps": chain.total_steps,
                "fully_exploitable": chain.fully_exploitable,
                "all_mitre_techniques": chain.all_mitre_techniques,
                "steps": [
                    {
                        "vuln_id": s.vuln_id,
                        "title": s.title,
                        "severity": s.severity,
                        "chain_position": s.chain_position,
                        "verification_status": s.verification_status,
                        "mitre_techniques": s.mitre_techniques,
                        "exploit_available": s.exploit_available,
                        "cvss_score": s.cvss_score,
                    }
                    for s in chain.steps
                ],
            })

        # Sort chains — fully exploitable first, then by severity
        output.sort(
            key=lambda c: (
                -int(c["fully_exploitable"]),
                -_SEVERITY_ORDER.get(c["max_severity"], 0),
            )
        )
        return output


def _max_severity_step(steps: List[AttackChainStep]) -> str:
    if not steps:
        return ""
    return max(steps, key=lambda s: _SEVERITY_ORDER.get(s.severity, 0)).title
