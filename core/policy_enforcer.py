"""
Zero-Trust Policy Enforcement Engine.
Maintains active session states, enforces dynamic quarantine and step-up auth,
and emits audit logs for SIEM integration.
"""
from datetime import datetime
from typing import Dict, List, Optional, Any
import json


class PolicyEnforcer:
    """Simulates production Zero-Trust Gateway enforcement (Envoy/Cloudflare Zero Trust style)."""

    def __init__(self):
        # Maps session_id -> session details
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        # List of structured audit events
        self.audit_log: List[Dict[str, Any]] = []
        # Blacklisted / Quarantined IPs and Users
        self.quarantined_ips: set = set()
        self.locked_users: set = set()

    def register_or_update_session(self, telemetry: Dict[str, Any], risk_evaluation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Applies zero-trust policy decisions to the session.
        """
        session_id = telemetry.get("session_id", "unknown_sess")
        user_id = telemetry.get("user_id", "unknown_user")
        ip_asn = telemetry.get("asn", "unknown_asn")
        city = telemetry.get("city", "Unknown")
        action = risk_evaluation["action"]
        risk_score = risk_evaluation["risk_score"]
        timestamp = telemetry.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        # Determine resulting session state
        if action == "ALLOW":
            state = "ACTIVE"
            enforcement_message = "Session trust verified. Unrestricted API access permitted."
        elif action == "CHALLENGE":
            state = "CHALLENGED"
            enforcement_message = "Step-up MFA triggered. Sensitive routes blocked pending verification."
        else:  # REVOKE
            state = "REVOKED"
            enforcement_message = "CRITICAL BREACH DETECTED: Session killed, IP quarantined, credentials frozen."
            self.quarantined_ips.add(ip_asn)
            self.locked_users.add(user_id)

        session_record = {
            "session_id": session_id,
            "user_id": user_id,
            "role": telemetry.get("role", "Administrator"),
            "city": city,
            "asn": ip_asn,
            "last_active": timestamp,
            "risk_score": risk_score,
            "risk_tier": risk_evaluation["risk_tier"],
            "state": state,
            "action_taken": action,
            "enforcement_message": enforcement_message,
            "active_triggers": risk_evaluation.get("active_triggers", []),
            "telemetry_snapshot": telemetry
        }

        self.active_sessions[session_id] = session_record

        # Generate SIEM Audit Event (Common Event Format / JSON style)
        audit_event = {
            "timestamp": timestamp,
            "event_id": f"EVT-{len(self.audit_log) + 1:06d}",
            "session_id": session_id,
            "user_id": user_id,
            "source_ip_asn": ip_asn,
            "location": city,
            "risk_score": risk_score,
            "action": action,
            "state": state,
            "details": enforcement_message,
            "triggers": risk_evaluation.get("active_triggers", [])
        }
        self.audit_log.insert(0, audit_event)  # Most recent first

        return session_record

    def submit_step_up_mfa(self, session_id: str, otp_code: str) -> Dict[str, Any]:
        """
        Simulates verifying an admin's dynamic step-up TOTP/Biometric challenge.
        For demo purposes: code '123456' or any 6-digit number succeeds.
        """
        if session_id not in self.active_sessions:
            return {"success": False, "message": f"Session {session_id} not found."}

        session = self.active_sessions[session_id]
        if session["state"] != "CHALLENGED":
            return {"success": False, "message": f"Session is in {session['state']} state, not awaiting step-up challenge."}

        if len(otp_code.strip()) == 6 and otp_code.strip().isdigit():
            session["state"] = "ACTIVE"
            session["risk_score"] = max(session["risk_score"] - 25.0, 15.0)
            session["enforcement_message"] = "Step-up MFA verified successfully. Temporary trust renewed."

            # Log audit event
            self.audit_log.insert(0, {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event_id": f"EVT-{len(self.audit_log) + 1:06d}",
                "session_id": session_id,
                "user_id": session["user_id"],
                "source_ip_asn": session["asn"],
                "location": session["city"],
                "risk_score": session["risk_score"],
                "action": "STEP_UP_VERIFIED",
                "state": "ACTIVE",
                "details": "Admin successfully answered step-up MFA challenge. Trust level elevated.",
                "triggers": ["Admin TOTP Challenge Passed"]
            })
            return {"success": True, "message": "Step-up authentication succeeded! Session restored to ACTIVE."}
        else:
            return {"success": False, "message": "Invalid OTP code. Must be a 6-digit numeric token."}

    def reset_quarantine(self, session_id: Optional[str] = None):
        """Allows security admin override to clear locks."""
        if session_id and session_id in self.active_sessions:
            sess = self.active_sessions[session_id]
            sess["state"] = "ACTIVE"
            sess["risk_score"] = 20.0
            if sess["user_id"] in self.locked_users:
                self.locked_users.remove(sess["user_id"])
            if sess["asn"] in self.quarantined_ips:
                self.quarantined_ips.remove(sess["asn"])
        else:
            self.quarantined_ips.clear()
            self.locked_users.clear()
            for s in self.active_sessions.values():
                s["state"] = "ACTIVE"
                s["risk_score"] = 15.0
