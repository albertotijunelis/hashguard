"""Admin dashboard router for HashGuard SaaS.

Provides admin-only endpoints for managing tenants, subscriptions,
usage metrics, and platform health.

All endpoints require admin role authentication.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from hashguard.logger import get_logger

logger = get_logger(__name__)

try:
    from fastapi import APIRouter, Depends, HTTPException, Query, Request
    from fastapi.responses import JSONResponse

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

if HAS_FASTAPI:
    router = APIRouter(prefix="/api/admin", tags=["Admin"])

    def _require_admin():
        """Dependency that requires admin role."""
        from hashguard.web.auth import _is_auth_enabled
        if not _is_auth_enabled():
            return None
        return None

    # We use a simpler approach: check admin in each endpoint
    def _check_admin(request: Request):
        from hashguard.web.auth import _is_auth_enabled, _extract_identity
        if not _is_auth_enabled():
            raise HTTPException(
                status_code=403,
                detail="Admin panel requires authentication. Set HASHGUARD_AUTH=1 and create an admin account.",
            )
        identity = _extract_identity(request)
        if not identity or identity.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Admin access required")
        return True

    # ── Tenant Management ───────────────────────────────────────────────────

    @router.get("/tenants")
    async def list_tenants(
        request: Request,
        page: int = Query(1, ge=1),
        per_page: int = Query(20, ge=1, le=100),
        search: str = Query("", max_length=200),
    ):
        """List all tenants with their plan and usage info."""
        _check_admin(request)
        from hashguard.models import get_orm_session, User, Subscription, UsageRecord
        from sqlalchemy import func, or_

        db = get_orm_session()
        try:
            query = db.query(User)
            if search:
                query = query.filter(
                    or_(
                        User.email.ilike(f"%{search}%"),
                        User.display_name.ilike(f"%{search}%"),
                    )
                )

            total = query.count()
            users = query.order_by(User.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()

            tenants = []
            for user in users:
                sub = db.query(Subscription).filter_by(
                    tenant_id=user.id, status="active"
                ).first()

                today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                usage = db.query(UsageRecord).filter_by(
                    tenant_id=user.id, period=today
                ).first()

                tenants.append({
                    "id": user.id,
                    "email": user.email,
                    "display_name": user.display_name,
                    "role": user.role,
                    "email_verified": user.email_verified,
                    "created_at": str(user.created_at),
                    "plan": sub.plan if sub else "free",
                    "analyses_today": usage.count if usage else 0,
                })

            return {
                "tenants": tenants,
                "total": total,
                "page": page,
                "per_page": per_page,
                "pages": (total + per_page - 1) // per_page,
            }
        finally:
            db.close()

    @router.get("/tenants/{tenant_id}")
    async def get_tenant_detail(request: Request, tenant_id: int):
        """Get detailed info about a specific tenant."""
        _check_admin(request)
        from hashguard.models import get_orm_session, User, Subscription, UsageRecord, Sample, APIKey
        from sqlalchemy import func

        db = get_orm_session()
        try:
            user = db.query(User).filter_by(id=tenant_id).first()
            if not user:
                raise HTTPException(status_code=404, detail="Tenant not found")

            sub = db.query(Subscription).filter_by(
                tenant_id=tenant_id, status="active"
            ).first()

            # Usage last 30 days
            thirty_days_ago = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
            usage_records = db.query(UsageRecord).filter(
                UsageRecord.tenant_id == tenant_id,
                UsageRecord.period >= thirty_days_ago,
            ).all()

            total_analyses = sum(r.count for r in usage_records)
            daily_usage = [{"date": r.period, "count": r.count} for r in usage_records]

            # Sample count
            sample_count = db.query(func.count(Sample.id)).filter_by(tenant_id=tenant_id).scalar() or 0

            # API keys
            api_keys = db.query(APIKey).filter_by(tenant_id=tenant_id).all()

            return {
                "id": user.id,
                "email": user.email,
                "display_name": user.display_name,
                "role": user.role,
                "email_verified": user.email_verified,
                "created_at": str(user.created_at),
                "plan": sub.plan if sub else "free",
                "stripe_customer_id": sub.stripe_customer_id if sub else None,
                "subscription_status": sub.status if sub else None,
                "analyses_30d": total_analyses,
                "daily_usage": daily_usage,
                "total_samples": sample_count,
                "api_keys": [
                    {
                        "id": k.id,
                        "name": k.name,
                        "created_at": str(k.created_at),
                        "last_used": str(k.last_used) if k.last_used else None,
                    }
                    for k in api_keys
                ],
            }
        finally:
            db.close()

    @router.put("/tenants/{tenant_id}/role")
    async def update_tenant_role(request: Request, tenant_id: int):
        """Update a tenant's role (admin, analyst, viewer)."""
        _check_admin(request)
        from hashguard.models import get_orm_session, User

        body = await request.json()
        new_role = body.get("role", "").strip().lower()
        if new_role not in ("admin", "analyst", "viewer"):
            raise HTTPException(status_code=400, detail="Invalid role. Must be: admin, analyst, viewer")

        db = get_orm_session()
        try:
            user = db.query(User).filter_by(id=tenant_id).first()
            if not user:
                raise HTTPException(status_code=404, detail="Tenant not found")
            user.role = new_role
            db.commit()
            return {"ok": True, "role": new_role}
        finally:
            db.close()

    @router.put("/tenants/{tenant_id}/plan")
    async def update_tenant_plan(request: Request, tenant_id: int):
        """Override a tenant's plan (admin bypass for Stripe)."""
        _check_admin(request)
        from hashguard.models import get_orm_session, User, Subscription

        body = await request.json()
        new_plan = body.get("plan", "").strip().lower()
        if new_plan not in ("free", "pro", "team", "enterprise"):
            raise HTTPException(status_code=400, detail="Invalid plan")

        db = get_orm_session()
        try:
            user = db.query(User).filter_by(id=tenant_id).first()
            if not user:
                raise HTTPException(status_code=404, detail="Tenant not found")

            sub = db.query(Subscription).filter_by(tenant_id=tenant_id, status="active").first()
            if sub:
                sub.plan = new_plan
            else:
                sub = Subscription(
                    tenant_id=tenant_id,
                    plan=new_plan,
                    status="active",
                    stripe_customer_id="admin_override",
                    stripe_subscription_id="admin_override",
                )
                db.add(sub)
            db.commit()
            return {"ok": True, "plan": new_plan}
        finally:
            db.close()

    # ── Platform Stats ──────────────────────────────────────────────────────

    @router.get("/stats")
    async def admin_stats(request: Request):
        """Platform-wide statistics for admin dashboard."""
        _check_admin(request)
        from hashguard.models import get_orm_session, User, Sample, Subscription, UsageRecord
        from sqlalchemy import func

        db = get_orm_session()
        try:
            total_users = db.query(func.count(User.id)).scalar() or 0
            verified_users = db.query(func.count(User.id)).filter_by(email_verified=True).scalar() or 0
            total_samples = db.query(func.count(Sample.id)).scalar() or 0

            # Plan distribution
            plan_counts = {}
            subs = db.query(Subscription.plan, func.count(Subscription.id)).filter_by(
                status="active"
            ).group_by(Subscription.plan).all()
            for plan, count in subs:
                plan_counts[plan] = count
            free_count = total_users - sum(plan_counts.values())
            plan_counts["free"] = max(0, free_count)

            # Analyses today
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            analyses_today = db.query(
                func.sum(UsageRecord.count)
            ).filter_by(period=today).scalar() or 0

            # Analyses last 7 days
            week_data = []
            for i in range(7):
                day = (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
                count = db.query(
                    func.sum(UsageRecord.count)
                ).filter_by(period=day).scalar() or 0
                week_data.append({"date": day, "count": count})

            # Revenue estimate
            from hashguard.web.billing import PLANS
            mrr = 0
            for plan, count in plan_counts.items():
                price = PLANS.get(plan, {}).get("price_monthly", 0)
                if price > 0:
                    mrr += price * count

            return {
                "total_users": total_users,
                "verified_users": verified_users,
                "total_samples": total_samples,
                "analyses_today": analyses_today,
                "plan_distribution": plan_counts,
                "weekly_analyses": list(reversed(week_data)),
                "mrr_estimate": mrr,
            }
        finally:
            db.close()

    # ── Activity Log ────────────────────────────────────────────────────────

    @router.get("/activity")
    async def admin_activity(
        request: Request,
        limit: int = Query(50, ge=1, le=200),
    ):
        """Recent platform activity (latest analyses, registrations)."""
        _check_admin(request)
        from hashguard.models import get_orm_session, User, Sample
        from sqlalchemy import desc

        db = get_orm_session()
        try:
            # Recent registrations
            recent_users = db.query(User).order_by(desc(User.created_at)).limit(10).all()
            registrations = [
                {
                    "type": "registration",
                    "email": u.email,
                    "display_name": u.display_name,
                    "timestamp": str(u.created_at),
                }
                for u in recent_users
            ]

            # Recent analyses
            recent_samples = db.query(Sample).order_by(desc(Sample.analysis_date)).limit(limit).all()
            analyses = [
                {
                    "type": "analysis",
                    "filename": s.filename,
                    "sha256": s.sha256,
                    "verdict": s.verdict,
                    "risk_score": s.risk_score,
                    "tenant_id": s.tenant_id,
                    "timestamp": str(s.analysis_date),
                }
                for s in recent_samples
            ]

            return {
                "recent_registrations": registrations,
                "recent_analyses": analyses,
            }
        finally:
            db.close()

    # ── Audit Log ───────────────────────────────────────────────────────────

    @router.get("/audit-logs")
    async def admin_audit_logs(
        request: Request,
        page: int = Query(1, ge=1),
        per_page: int = Query(50, ge=1, le=200),
        action: str = Query("", max_length=100),
        tenant_id: str = Query("", max_length=100),
        user_id: Optional[int] = Query(None),
    ):
        """Query immutable audit trail with filters."""
        _check_admin(request)
        from hashguard.models import get_orm_session, AuditLog
        from sqlalchemy import desc

        db = get_orm_session()
        try:
            query = db.query(AuditLog)
            if action:
                query = query.filter(AuditLog.action == action)
            if tenant_id:
                query = query.filter(AuditLog.tenant_id == tenant_id)
            if user_id is not None:
                query = query.filter(AuditLog.user_id == user_id)

            total = query.count()
            logs = (
                query.order_by(desc(AuditLog.created_at))
                .offset((page - 1) * per_page)
                .limit(per_page)
                .all()
            )

            return {
                "logs": [
                    {
                        "id": log.id,
                        "tenant_id": log.tenant_id,
                        "user_id": log.user_id,
                        "action": log.action,
                        "resource_type": log.resource_type,
                        "resource_id": log.resource_id,
                        "details": log.details,
                        "ip_address": log.ip_address,
                        "created_at": log.created_at.isoformat() if log.created_at else None,
                    }
                    for log in logs
                ],
                "total": total,
                "page": page,
                "per_page": per_page,
                "pages": (total + per_page - 1) // per_page,
            }
        finally:
            db.close()

    @router.get("/audit-logs/actions")
    async def audit_log_actions(request: Request):
        """List all distinct audit log action types."""
        _check_admin(request)
        from hashguard.models import get_orm_session, AuditLog
        from sqlalchemy import distinct

        db = get_orm_session()
        try:
            actions = [
                row[0]
                for row in db.query(distinct(AuditLog.action)).order_by(AuditLog.action).all()
            ]
            return {"actions": actions}
        finally:
            db.close()
