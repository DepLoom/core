"""Root-model scope and whole-tree resolution have different authority."""
import unittest
from unittest.mock import patch
import test_draft_partial_owner_contract as fixtures

class DraftModelCoverageTests(unittest.TestCase):
    def publish(self, *args, **kwargs):
        return fixtures.PartialOwnerContractTests.publish(self, *args, **kwargs)

    def test_default_declares_root_scope_without_full_tree_claim(self):
        result, plan, prompt = self.publish([fixtures.row()], {})
        self.assertEqual('DECLARED_PACKAGE_PEERS_AND_ENVIRONMENT', result['constraintModel']['scope'])
        self.assertEqual('NOT_MODELED', result['constraintModel']['transitivePlacement'])
        self.assertEqual('NOT_RUN', result['packageManagerValidation']['status'])
        self.assertEqual(result['constraintModel'], plan['constraintModel'])
        self.assertIn('transitive', prompt.lower())
        self.assertEqual('UNKNOWN', result['compatibility'])

    def test_failed_resolution_blocks_readiness_without_false_unsat(self):
        evidence = {'status': 'RESOLUTION_FAILED', 'learningAllowed': False, 'projects': {'fixture': {'status': 'RESOLUTION_FAILED', 'code': 'ERESOLVE'}}}
        with patch('draft_npm_preflight.validate_draft_plan', return_value=evidence):
            result, plan, prompt = self.publish([fixtures.row()], {}, npm_preflight={'timeoutSeconds': 20})
        self.assertEqual('DRAFT_PARTIAL', result['status'])
        self.assertFalse(result['packageManagerValidation']['learningAllowed'])
        self.assertEqual(1, plan['counts']['proposed'])
        self.assertEqual('NOT_VERIFIED', result['verificationStatus'])
        self.assertIn('PM_VALIDATION_FAILED', prompt)
        self.assertNotIn('UNSAT', result['partialReason'])

    def test_resolution_pass_does_not_grant_install_or_runtime_authority(self):
        evidence = {'status': 'RESOLUTION_PASSED', 'learningAllowed': False, 'projects': {}}
        with patch('draft_npm_preflight.validate_draft_plan', return_value=evidence):
            result, plan, _ = self.publish([fixtures.row()], {}, npm_preflight={'timeoutSeconds': 20})
        self.assertEqual('DRAFT_READY', result['status'])
        self.assertEqual('NOT_VERIFIED', result['verificationStatus'])
        self.assertEqual('UNKNOWN', result['compatibility'])
        self.assertEqual('NOT_MODELED', result['constraintModel']['transitivePlacement'])

    def test_unknown_is_not_a_conflict_or_resolution_pass(self):
        evidence = {'status': 'UNKNOWN', 'learningAllowed': False, 'projects': {'fixture': {'status': 'UNKNOWN', 'code': 'ENOTCACHED'}}}
        with patch('draft_npm_preflight.validate_draft_plan', return_value=evidence):
            result, plan, _ = self.publish([fixtures.row()], {}, npm_preflight={'timeoutSeconds': 20})
        self.assertEqual('DRAFT_PARTIAL', result['status'])
        self.assertEqual('UNKNOWN', result['packageManagerValidation']['status'])
        self.assertIn('PM_VALIDATION_UNKNOWN', preflight_notice := __import__('draft_npm_preflight').validation_notice(result['packageManagerValidation'], 'ru'))
        self.assertNotIn('PM_VALIDATION_FAILED', preflight_notice)
        self.assertEqual(1, result['metadata']['postPlanScopeTotal'])
        self.assertEqual('UNKNOWN', result['compatibility'])

    def test_runtime_registry_never_comes_from_redacted_display_context(self):
        registry = 'https://registry.example.invalid/repository/custom-feed/'
        evidence = {'status': 'RESOLUTION_FAILED', 'learningAllowed': False, 'projects': {}}
        with patch('draft_npm_preflight.validate_draft_plan', return_value=evidence) as check:
            self.publish([fixtures.row()], {}, npm_preflight={'registry': registry},
                         execution_context={'registry': 'https://registry.example.invalid/repository/[redacted]/'})
        self.assertEqual(registry, check.call_args.kwargs['registry'])

if __name__ == '__main__':
    unittest.main()
