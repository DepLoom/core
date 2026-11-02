"""Explicit finite-root choice using production peer extraction and unchanged Z3.

Declared-root IR only: no registry fetch, full npm placement, health or runtime proof.
The versioned objective is primary version, fewer changed roots, then low-version
lexicographic tie-break by sorted package name. Major budget is part of the IR.
"""
from __future__ import annotations
import dataclasses
import itertools
import re
from types import SimpleNamespace
from semantic_version import NpmSpec, Version
from peer_solver_model import PackageVariable, forbidden

OBJECTIVE = 'PRIMARY_VERSION_THEN_MIN_CHANGES_V1'
_VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z')

class GoalChoiceUnsupported(ValueError):
    pass

def build_goal_choice_model(current, domains, records, *, node_version, project_dir,
                            primary_package, max_major_changes, constraint_limit=4096):
    """Inputs must contain every declared root; held roots have singleton domains."""
    from dependency_live_roadmap_generator import DependencyRow, _build_peer_optimization_model
    if (not isinstance(current, dict) or not current or len(current)>256
            or set(current)!=set(domains) or set(current)!=set(records)
            or primary_package not in current or not _VERSION.fullmatch(node_version)
            or type(max_major_changes) is not int or not 0<=max_major_changes<=len(current)
            or type(constraint_limit) is not int or not 1<=constraint_limit<=4096):
        raise GoalChoiceUnsupported('INVALID_CHOICE_INPUT')
    rows, cache, normalized = {}, {}, {}
    for name in sorted(current):
        values=domains[name]
        if (not isinstance(current[name],str) or not _VERSION.fullmatch(current[name])
                or not isinstance(values,list) or not 1<=len(values)<=32
                or any(not isinstance(v,str) or not _VERSION.fullmatch(v) for v in values)
                or len(set(values))!=len(values) or not isinstance(records[name],dict)):
            raise GoalChoiceUnsupported('INVALID_CHOICE_DOMAIN')
        normalized[name]=sorted(values,key=Version)
        for version in values:
            meta=records[name].get(version)
            if not isinstance(meta,dict) or meta.get('name')!=name or meta.get('version')!=version:
                raise GoalChoiceUnsupported('METADATA_INCOMPLETE_OR_MISMATCH')
            peers=meta.get('peerDependencies',{})
            engines=meta.get('engines',{})
            peer_meta=meta.get('peerDependenciesMeta',{})
            if not isinstance(peers,dict) or not isinstance(engines,dict) or not isinstance(peer_meta,dict):
                raise GoalChoiceUnsupported('METADATA_UNSUPPORTED')
            try:
                for spec in [*peers.values(),*([engines['node']] if 'node' in engines else [])]:
                    if not isinstance(spec,str) or not spec.strip():raise ValueError()
                    NpmSpec(spec)
                for entry in peer_meta.values():
                    if not isinstance(entry,dict) or ('optional' in entry and type(entry['optional']) is not bool):raise ValueError()
            except (ValueError,TypeError):
                raise GoalChoiceUnsupported('METADATA_RANGE_UNSUPPORTED') from None
        cache[name]={'versions':records[name]}
        fields={key:'' for key in ('current_vulns','min_no_critical','min_no_high','min_no_vuln',
                'min_lag_12m','min_lag_9m','min_lag_6m','min_lag_3m','reason','notes')}
        rows[name]=DependencyRow(project='finite-goal',package_dir=str(project_dir),name=name,
            kind='runtime',requested_spec=current[name],current_version=current[name],current_source='host-lock',
            latest_version=normalized[name][-1],group=0,node_version_override=node_version,**fields)
    # Explicit intent avoids ambient mutable global intent; strict_current removes
    # the legacy current/current exemption only for this new opt-in contract.
    model=_build_peer_optimization_model(list(rows),rows,normalized,SimpleNamespace(npm_cache=cache),'default',
        intent_policies={name:'auto' for name in rows},strict_current=True)
    changing=[(name,version) for name in sorted(rows) for version in normalized[name]
              if Version(version).major!=Version(current[name]).major]
    budget=[]
    # Bound enumeration before expanding a potentially exponential conjunction set.
    groups={name:[v for n,v in changing if n==name] for name in sorted({n for n,v in changing})}
    count=0
    for names in itertools.combinations(groups,max_major_changes+1):
        size=1
        for name in names:size*=len(groups[name])
        count+=size
        if count>constraint_limit:raise GoalChoiceUnsupported('MAJOR_BUDGET_IR_LIMIT')
        for versions in itertools.product(*(groups[name] for name in names)):
            budget.append(forbidden(zip(names,versions),reason='USER_MAJOR_CHANGE_BUDGET',provenance='finite-goal-policy-v1'))
    names=sorted(rows);width=2+len(names);packages=[]
    for name in names:
        scores=[]
        for rank,version in enumerate(normalized[name]):
            score=[0]*width
            if name==primary_package:score[0]=rank
            score[1]=-int(version!=current[name])
            score[2+names.index(name)]=-rank
            scores.append((version,tuple(score)))
        packages.append(PackageVariable(name,current[name],tuple(normalized[name]),tuple(scores)))
    model=dataclasses.replace(model,packages=tuple(packages),objective_width=width).with_constraints(budget)
    if model.validation_issue():raise GoalChoiceUnsupported('INVALID_CHOICE_MODEL')
    return model

def solve_goal_choice(model, *, timeout_ms=10000):
    from peer_solver_z3 import solve_z3_exact
    if type(timeout_ms) is not int or not 100<=timeout_ms<=30000:
        raise GoalChoiceUnsupported('INVALID_CHOICE_TIMEOUT')
    result=solve_z3_exact(model,timeout_ms=timeout_ms)
    if result.status=='optimal' and (not isinstance(result.assignment,dict)
            or set(result.assignment)!=set(model.package_map()) or model.assignment_issue(result.assignment)
            or result.score!=model.assignment_score(result.assignment)):
        raise GoalChoiceUnsupported('INVALID_CHOICE_SOLVER_RESULT')
    return result
