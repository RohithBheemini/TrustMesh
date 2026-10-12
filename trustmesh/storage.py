"""
TrustMesh Durable Storage & Audit Persistence
Provides SQLAlchemy-backed durable logging and revocation storage for production environments.
"""

from __future__ import annotations
import json
from typing import List
from sqlalchemy import create_engine, Column, Integer, String, Text
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session

from trustmesh.policy import PolicyDecision
from trustmesh.revocation import RevocationReceipt

Base = declarative_base()


class AuditRecordModel(Base):
    __tablename__ = "trustmesh_audit_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    decision = Column(String(32), nullable=False)
    code = Column(String(64), nullable=False)
    reason = Column(Text, nullable=False)
    invoking_agent = Column(String(128), nullable=False)
    target_resource = Column(String(256), nullable=False)
    target_action = Column(String(64), nullable=False)
    chain_depth = Column(Integer, default=0)
    token_id = Column(String(64), nullable=True)
    evaluated_caveats_json = Column(Text, default="{}")
    timestamp = Column(Integer, nullable=False)
    verifier_did = Column(String(128), nullable=False)
    receipt_signature = Column(Text, nullable=False)


class RevocationRecordModel(Base):
    __tablename__ = "trustmesh_revocations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(String(128), unique=True, nullable=False)
    target_type = Column(String(32), nullable=False)
    reason = Column(Text, nullable=False)
    revoked_at = Column(Integer, nullable=False)
    authority_did = Column(String(128), nullable=False)
    signature = Column(Text, nullable=False)


class AuditStorage:
    """Production database manager for persisting cryptographic receipts and revocation state."""

    def __init__(self, db_url: str = "sqlite:///trustmesh_audit.db"):
        self.engine = create_engine(db_url, connect_args={"check_same_thread": False} if "sqlite" in db_url else {})
        Base.metadata.create_all(self.engine)
        self.session_factory = scoped_session(sessionmaker(bind=self.engine))

    def record_decision(self, decision: PolicyDecision) -> None:
        """Persist a cryptographic policy decision receipt."""
        session = self.session_factory()
        try:
            record = AuditRecordModel(
                decision=decision.decision,
                code=decision.code,
                reason=decision.reason,
                invoking_agent=decision.invoking_agent,
                target_resource=decision.target_resource,
                target_action=decision.target_action,
                chain_depth=decision.chain_depth,
                token_id=decision.token_id,
                evaluated_caveats_json=json.dumps(decision.evaluated_caveats),
                timestamp=decision.timestamp,
                verifier_did=decision.verifier_did,
                receipt_signature=decision.receipt_signature,
            )
            session.add(record)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_recent_decisions(self, limit: int = 50) -> List[PolicyDecision]:
        """Fetch the most recent policy enforcement decisions."""
        session = self.session_factory()
        try:
            records = (
                session.query(AuditRecordModel)
                .order_by(AuditRecordModel.timestamp.desc(), AuditRecordModel.id.desc())
                .limit(limit)
                .all()
            )
            decisions = []
            for r in records:
                caveats = {}
                try:
                    caveats = json.loads(r.evaluated_caveats_json)
                except Exception:
                    pass
                dec = PolicyDecision(
                    decision=r.decision,
                    code=r.code,
                    reason=r.reason,
                    invoking_agent=r.invoking_agent,
                    target_resource=r.target_resource,
                    target_action=r.target_action,
                    chain_depth=r.chain_depth,
                    token_id=r.token_id,
                    evaluated_caveats=caveats,
                    timestamp=r.timestamp,
                    verifier_did=r.verifier_did,
                    receipt_signature=r.receipt_signature,
                )
                decisions.append(dec)
            return decisions
        finally:
            session.close()

    def record_revocation(self, receipt: RevocationReceipt) -> None:
        """Persist a signed revocation disavowal."""
        session = self.session_factory()
        try:
            existing = session.query(RevocationRecordModel).filter_by(target_id=receipt.target_id).first()
            if not existing:
                rec = RevocationRecordModel(
                    target_id=receipt.target_id,
                    target_type=receipt.target_type,
                    reason=receipt.reason,
                    revoked_at=receipt.revoked_at,
                    authority_did=receipt.authority_did,
                    signature=receipt.signature,
                )
                session.add(rec)
                session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_revoked_ids(self) -> List[str]:
        """Fetch all revoked target IDs."""
        session = self.session_factory()
        try:
            records = session.query(RevocationRecordModel.target_id).all()
            return [r[0] for r in records]
        finally:
            session.close()
