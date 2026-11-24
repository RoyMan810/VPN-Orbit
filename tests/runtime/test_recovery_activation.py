import time
import unittest

from vpn_orbit.errors import Denied
from vpn_orbit.runtime.activation import validate_review


class ActivationReviewTests(unittest.TestCase):
    def setUp(self):
        self.binding = {"v": 1, "archive_sha256": "a" * 64, "destination": "b" * 64, "policy_sha256": "c" * 64,
                        "targets": ["fixture"]}
        self.review = {"binding": self.binding, "source_fenced": True, "evidence": "isolated lab network",
                       "confirmed_at": int(time.time()),
                       "targets": {"fixture": {"no_outstanding_effects": True, "postconditions_verified": True}}}

    def test_explicit_fencing_and_local_inventory_are_required(self):
        self.assertEqual(len(validate_review(self.review, self.binding)), 64)
        for replacement, expected in (
            ({"source_fenced": False}, "ACTIVATION_FENCING_REQUIRED"),
            ({"binding": {**self.binding, "destination": "d" * 64}}, "ACTIVATION_FENCING_REQUIRED"),
            ({"targets": {}}, "ACTIVATION_INVENTORY_INCOMPLETE"),
            ({"targets": {"fixture": {"no_outstanding_effects": False, "postconditions_verified": True}}},
             "ACTIVATION_RECONCILIATION_REQUIRED"),
            ({"confirmed_at": int(time.time()) - 3601}, "ACTIVATION_CONFIRMATION_EXPIRED"),
        ):
            with self.subTest(expected=expected), self.assertRaisesRegex(Denied, expected):
                validate_review({**self.review, **replacement}, self.binding)
