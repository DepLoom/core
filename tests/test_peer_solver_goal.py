import copy
import itertools
import tempfile
import unittest
from unittest.mock import patch
from peer_solver_goal import build_goal_choice_model, solve_goal_choice, GoalChoiceUnsupported

class GoalChoiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.current={'engine':'6.4.5','plugin':'4.3.4','held':'1.0.0'}
        self.domains={'engine':['6.4.5','7.0.0'],'plugin':['4.3.4','4.5.2','5.0.0'],'held':['1.0.0']}
        self.records={n:{v:{'name':n,'version':v} for v in vs} for n,vs in self.domains.items()}
        for v,spec in [('4.3.4','^6'),('4.5.2','^6 || ^7'),('5.0.0','^6 || ^7')]:
            self.records['plugin'][v]['peerDependencies']={'engine':spec}
    def model(self,**kw):
        return build_goal_choice_model(self.current,self.domains,self.records,node_version='24.18.0',
            project_dir=self.tmp.name,primary_package='engine',max_major_changes=1,**kw)
    def test_optimum_and_all_six_against_independent_expected_truth(self):
        m=self.model();valid=[]
        for engine,plugin in itertools.product(self.domains['engine'],self.domains['plugin']):
            assignment={'engine':engine,'plugin':plugin,'held':'1.0.0'}
            expected=(engine=='6.4.5' or plugin=='4.5.2')
            self.assertEqual(not bool(m.assignment_issue(assignment)),expected,(engine,plugin))
            if expected:valid.append(assignment)
        self.assertEqual(len(valid),4)
        r=solve_goal_choice(m)
        self.assertEqual(r.status,'optimal');self.assertEqual(r.assignment,{'engine':'7.0.0','plugin':'4.5.2','held':'1.0.0'})
        self.assertEqual(r.score,m.assignment_score(r.assignment))
    def test_current_current_and_engine_are_not_grandfathered(self):
        self.records['plugin']['4.3.4']['peerDependencies']={'engine':'^8'}
        self.assertTrue(self.model().assignment_issue(self.current))
        self.records['held']['1.0.0']['engines']={'node':'<20'}
        self.assertEqual(solve_goal_choice(self.model()).status,'unsat')
    def test_ambient_intent_not_read(self):
        with patch('dependency_live_roadmap_generator._baseline_intent_payload',side_effect=AssertionError('ambient intent')):
            self.assertEqual(solve_goal_choice(self.model()).status,'optimal')
    def test_missing_or_bad_metadata_fails_closed(self):
        for mutate in [lambda r:r['engine'].pop('7.0.0'),lambda r:r['held']['1.0.0'].update(name='wrong'),
                lambda r:r['plugin']['4.3.4'].update(peerDependencies={'engine':'git+https://invalid'}),
                lambda r:r['held']['1.0.0'].update(engines={'node':True})]:
            original=copy.deepcopy(self.records);mutate(self.records)
            with self.assertRaises(GoalChoiceUnsupported):self.model()
            self.records=original
    def test_budget_is_inside_ir_and_bounded(self):
        m=self.model();self.assertTrue(any(c.reason=='USER_MAJOR_CHANGE_BUDGET' for c in m.constraints))
        self.domains['held']=['1.0.0','2.0.0'];self.records['held']['2.0.0']={'name':'held','version':'2.0.0'}
        with self.assertRaisesRegex(GoalChoiceUnsupported,'IR_LIMIT'):self.model(constraint_limit=1)
    def test_unknown_never_promoted(self):
        from peer_solver_model import ExactSolveResult
        with patch('peer_solver_z3.solve_z3_exact',return_value=ExactSolveResult('z3','unknown')):
            self.assertEqual(solve_goal_choice(self.model()).status,'unknown')
    def test_incomplete_optimal_result_rejected(self):
        from peer_solver_model import ExactSolveResult
        with patch('peer_solver_z3.solve_z3_exact',return_value=ExactSolveResult('z3','optimal',assignment={'engine':'7.0.0'},score=(1,))):
            with self.assertRaisesRegex(GoalChoiceUnsupported,'INVALID_CHOICE_SOLVER_RESULT'):solve_goal_choice(self.model())

    def test_held_prerelease_is_exact_and_does_not_expand_target_domain(self):
        old=self.records['held'].pop('1.0.0');old['version']='1.0.0-alpha.23'
        self.current['held']='1.0.0-alpha.23';self.domains['held']=['1.0.0-alpha.23'];self.records['held']['1.0.0-alpha.23']=old
        result=solve_goal_choice(self.model())
        self.assertEqual(result.status,'optimal');self.assertEqual(result.assignment['held'],'1.0.0-alpha.23')
        self.assertEqual(result.assignment['engine'],'7.0.0')
        self.domains['held'].append('1.0.0')
        with self.assertRaises(GoalChoiceUnsupported):self.model()
    def test_malformed_or_ranged_source_versions_are_not_exact_held_versions(self):
        for version in ['^1.0.0','1.0','v1.0.0','1.0.0-alpha..1','1.0.0 || 2.0.0']:
            with self.subTest(version=version):
                self.current['held']=version;self.domains['held']=[version]
                with self.assertRaises(GoalChoiceUnsupported):self.model()

if __name__=='__main__':unittest.main()
