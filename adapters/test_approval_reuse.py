"""Scoped approval lifecycle tests. All state and actions are synthetic."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
import unittest
from unittest.mock import patch

from adapters import test_context as Fixtures
import reviews as R


class ScopedReviewTests(Fixtures.StateFixture):
    def setUp(self):
        super().setUp()
        self.args = {"command": "synthetic-command", "cwd": str(self.tmp),
                     "executor": os.path.realpath(__file__), "environment_sha256": "a" * 64,
                     "execution_contract": "guard-v1", "stdin": "closed", "shell_startup": "disabled"}
        self.context = {"root": str(self.tmp), "mode": "strict", "assessment": "b" * 64}

    def pending(self, attempt="probe", **kwargs):
        return R.pending("codex", "s1", str(self.tmp), "guarded_shell",
                         kwargs.pop("args", self.args), self.verdict,
                         context=kwargs.pop("context", self.context), attempt_id=attempt, **kwargs)

    def approve(self, scope="once"):
        rid, _ = self.pending()
        nonce, row = R.claim(rid, "s1")
        self.assertEqual(R.finish(rid, "s1", nonce, "approved", scope=scope), "approved")
        return rid, R.details(rid, "s1")

    def test_spent_once_allows_new_review_not_replayed_execution(self):
        rid, row = self.approve()
        self.assertTrue(R.consume(rid, "s1", row["sha"], attempt_id="execution-1"))
        self.assertFalse(R.consume(rid, "s1", row["sha"], attempt_id="execution-1"))
        self.assertEqual(self.pending("execution-1"), (rid, "used"))
        new, status = self.pending("execution-2")
        self.assertEqual(status, "pending")
        self.assertNotEqual(new, rid)
        self.assertEqual(R.details(rid, "s1")["status"], "used")

    def test_timed_grant_reuses_without_extending_deadline(self):
        rid, row = self.approve("same_action_15m")
        self.assertEqual(row["expires"], row["approved_at"] + 900)
        for call in ("execution-1", "execution-2"):
            self.assertEqual(self.pending(call, turn_id=call), (rid, "approved"))
            self.assertTrue(R.consume(rid, "s1", row["sha"], attempt_id=call))
        after = R.details(rid, "s1")
        self.assertEqual(after["expires"], row["expires"])
        self.assertEqual(after["uses"], 2)
        self.assertFalse(R.consume(rid, "s1", row["sha"], attempt_id="execution-2"))

    def test_timed_grant_expires_and_requires_fresh_review(self):
        rid, row = self.approve("same_action_15m")
        with patch.object(R.time, "time", return_value=row["expires"] + 1):
            self.assertFalse(R.consume(rid, "s1", row["sha"], attempt_id="late"))
            new, status = self.pending("late")
            self.assertNotEqual(new, rid)
            self.assertEqual(status, "pending")

    def test_approval_deadline_starts_at_response_not_request_creation(self):
        rid, _ = self.pending()
        nonce, row = R.claim(rid, "s1")
        with patch.object(R.time, "time", return_value=row["created"] + 60):
            R.finish(rid, "s1", nonce, "approved", scope="same_action_15m")
        self.assertEqual(R.details(rid, "s1")["expires"], row["created"] + 960)

    def test_changed_scope_never_matches_timed_grant(self):
        rid, row = self.approve("same_action_15m")
        for key, value in (("root", str(self.tmp / "other")), ("mode", "normal"),
                           ("assessment", "c" * 64)):
            with self.subTest(key=key):
                context = {**self.context, key: value}
                sha = R.binding("codex", "s1", str(self.tmp), "guarded_shell", self.args, context)
                self.assertFalse(R.consume(rid, "s1", sha, attempt_id=key))
                self.assertEqual(self.pending(key, context=context)[1], "pending")
        for key, value in (("command", "different-command"), ("cwd", str(self.tmp / "other")),
                           ("executor", str(self.tmp / "other-shell")),
                           ("environment_sha256", "d" * 64), ("execution_contract", "guard-v2")):
            with self.subTest(key=key):
                args = {**self.args, key: value}
                sha = R.binding("codex", "s1", str(self.tmp), "guarded_shell", args, self.context)
                self.assertFalse(R.consume(rid, "s1", sha, attempt_id=key))
        self.assertEqual(R.details(rid, "s1")["uses"], 0)

    def test_timed_grant_requires_unique_host_attempt(self):
        rid, row = self.approve("same_action_15m")
        self.assertFalse(R.consume(rid, "s1", row["sha"]))
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: R.consume(rid, "s1", row["sha"], attempt_id="same-call"), range(8)))
        self.assertEqual(sum(results), 1)

    def test_denial_and_unanswered_expiry_cannot_prompt_again(self):
        for status in ("denied", "cancelled", "timed-out", "client-declined",
                       "review-unavailable", "invalid-response"):
            args = {**self.args, "command": status}
            rid, _ = self.pending(args=args)
            nonce, _ = R.claim(rid, "s1")
            R.finish(rid, "s1", nonce, status)
            self.assertEqual(self.pending("another-call", args=args), (rid, status))
        rid, _ = self.pending(args={**self.args, "command": "unanswered"})
        row = R.details(rid, "s1")
        with patch.object(R.time, "time", return_value=row["expires"] + 1):
            self.assertEqual(self.pending("late", args=row["args"]), (rid, "expired"))

    def test_unguarded_actions_cannot_receive_timed_grant(self):
        rid, _ = R.pending("codex", "s1", str(self.tmp), "apply_patch", {}, self.verdict)
        nonce, _ = R.claim(rid, "s1")
        self.assertEqual(R.finish(rid, "s1", nonce, "approved", scope="same_action_15m"), "invalid-response")

    def test_legacy_approval_remains_one_time(self):
        rid, row = self.approve()
        with R._store() as data:
            for key in ("approval_scope", "approved_at", "uses", "attempts"):
                data[rid].pop(key, None)
        self.assertTrue(R.consume(rid, "s1", row["sha"], attempt_id="first"))
        self.assertFalse(R.consume(rid, "s1", row["sha"], attempt_id="second"))

    def test_grant_use_limit_never_rotates_into_another_approval(self):
        rid, row = self.approve("same_action_15m")
        with patch.object(R, "MAX_USES", 1):
            self.assertTrue(R.consume(rid, "s1", row["sha"], attempt_id="first"))
            with self.assertRaises(ValueError):
                R.consume(rid, "s1", row["sha"], attempt_id="second")
        self.assertEqual(self.pending("second"), (rid, "approved"))
        self.assertEqual(R.details(rid, "s1")["uses"], 1)

    def test_another_session_cannot_use_the_timed_grant(self):
        rid, row = self.approve("same_action_15m")
        with self.assertRaises(ValueError):
            R.consume(rid, "other-session", row["sha"], attempt_id="first")
        self.assertEqual(R.details(rid, "s1")["uses"], 0)

    def test_approval_replay_cannot_extend_a_timed_grant(self):
        rid, _ = self.pending()
        nonce, _ = R.claim(rid, "s1")
        R.finish(rid, "s1", nonce, "approved", scope="same_action_15m")
        row = R.details(rid, "s1")
        with patch.object(R.time, "time", return_value=row["approved_at"] + 100):
            R.finish(rid, "s1", nonce, "approved", scope="same_action_15m")
        self.assertEqual(R.details(rid, "s1")["expires"], row["expires"])


class ScopedFormTests(Fixtures.StateFixture, unittest.IsolatedAsyncioTestCase):
    client = Fixtures.ApprovalTests.client

    @classmethod
    def setUpClass(cls):
        import approval_mcp
        cls.M = approval_mcp

    async def test_guarded_form_offers_explicit_timed_choice(self):
        args = {"command": "inert", "cwd": str(self.tmp), "executor": os.path.realpath(__file__),
                "environment_sha256": "a" * 64, "execution_contract": "guard-v1",
                "stdin": "closed", "shell_startup": "disabled"}
        rid, _ = R.pending("codex", "s1", str(self.tmp), "guarded_shell", args, self.verdict,
                           context={"root": str(self.tmp), "mode": "strict", "assessment": "b" * 64})
        result = await self.M.request_review(rid, self.client([
            ("accept", {"decision": "Allow same action for 15 minutes"})]))
        self.assertTrue(result["approved"])
        self.assertEqual(result["scope"], "same_action_15m")
        self.assertIn("Allow same action for 15 minutes", self.sent[0][1]["properties"]["decision"]["enum"])
        self.assertEqual(result["expires_at"], R.details(rid, "s1")["expires"])

    async def test_unguarded_form_only_offers_once(self):
        rid, _ = self.pending()
        result = await self.M.request_review(rid, self.client([("accept", {"decision": "Approve once"})]))
        self.assertTrue(result["approved"])
        self.assertEqual(result["scope"], "once")
        self.assertNotIn("Allow same action for 15 minutes", self.sent[0][1]["properties"]["decision"]["enum"])

    async def test_unguarded_timed_response_cannot_grant_permission(self):
        rid, _ = self.pending()
        result = await self.M.request_review(rid, self.client([
            ("accept", {"decision": "Allow same action for 15 minutes"})]))
        self.assertFalse(result["approved"])
        self.assertEqual(result["status"], "invalid-response")

    async def test_more_information_can_finish_with_timed_approval(self):
        args = {"command": "inert", "cwd": str(self.tmp), "executor": os.path.realpath(__file__),
                "environment_sha256": "a" * 64, "execution_contract": "guard-v1",
                "stdin": "closed", "shell_startup": "disabled"}
        rid, _ = R.pending("codex", "s1", str(self.tmp), "guarded_shell", args, self.verdict,
                           context={"root": str(self.tmp), "mode": "strict", "assessment": "b" * 64})
        result = await self.M.request_review(rid, self.client([
            ("accept", {"decision": "More information"}),
            ("accept", {"decision": "Allow same action for 15 minutes"})]))
        self.assertTrue(result["approved"])
        self.assertEqual(result["scope"], "same_action_15m")
        self.assertEqual(len(self.sent), 2)
        self.assertEqual(self.sent[1][1]["properties"]["decision"]["enum"],
                         ["Approve once", "Allow same action for 15 minutes", "Deny"])
