"""Explicit lifecycle execution policy must participate in verification identity."""
import unittest
from unittest.mock import patch
import baseline_constraint_verifier as v
from verification_proof import environment_snapshot_fingerprint

class LifecyclePolicyTests(unittest.TestCase):
    def test_legacy_default_and_explicit_deny(self):
        self.assertTrue(v.BaselineVerifyConfig.from_mapping({}).lifecycle_scripts)
        self.assertFalse(v.BaselineVerifyConfig.from_mapping({'lifecycleScripts':False}).lifecycle_scripts)
    def test_opposite_lifecycle_policies_cannot_share_environment_proof(self):
        allow=v._verification_environment(v.BaselineVerifyConfig(lifecycle_scripts=True))
        deny=v._verification_environment(v.BaselineVerifyConfig(lifecycle_scripts=False))
        self.assertNotEqual(environment_snapshot_fingerprint(allow),environment_snapshot_fingerprint(deny))
    def test_ambient_policy_claim_cannot_override_config(self):
        with patch.dict('os.environ',{'DEPLOOM_VERIFIER_LIFECYCLE_SCRIPTS':'allow'}):
            self.assertEqual(v._verification_environment(v.BaselineVerifyConfig(lifecycle_scripts=False))['DEPLOOM_VERIFIER_LIFECYCLE_SCRIPTS'],'deny')
    def test_preparation_coordination_separates_lifecycle_policies(self):
        from pathlib import Path
        a=v._preparation_coordination_key(Path.cwd(),{'demo':'1.0.0'},(),v.BaselineVerifyConfig(lifecycle_scripts=True))
        b=v._preparation_coordination_key(Path.cwd(),{'demo':'1.0.0'},(),v.BaselineVerifyConfig(lifecycle_scripts=False))
        self.assertNotEqual(a,b)

if __name__=='__main__':unittest.main()
