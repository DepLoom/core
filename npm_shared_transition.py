"""Exact host-enumerated shared npm transitions; no execution authority or proof.

Only a pinned operator registry may supply the contract. Pure validation is not
consent, publisher evidence, installability, runtime compatibility or acceptance.
"""
from pathlib import PurePosixPath
import hashlib,json
from semantic_version import NpmSpec,Version
from project_runtime import normalize_npm_range

class SharedTransitionError(ValueError):pass

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()

def _fail(code):raise SharedTransitionError('SHARED_TRANSITION_'+code)

def _resolve(packages,owner,name,peer=False):
    parent=owner
    if peer and owner:parent=owner.rsplit('/node_modules/',1)[0] if '/node_modules/' in owner else ''
    for loc in [parent]+[p.as_posix() for p in PurePosixPath(parent).parents]:
        if loc=='.':loc=''
        path=(loc+'/' if loc else '')+'node_modules/'+name
        if path in packages:return path
    return None

def _incoming(packages,path):
    rows=[]
    for owner,record in packages.items():
        sections=('dependencies','optionalDependencies','peerDependencies')+ (('devDependencies',) if not owner else ())
        for section in sections:
            edges=record.get(section,{})
            if not isinstance(edges,dict):_fail('INVALID_EDGES')
            for name,spec in edges.items():
                if _resolve(packages,owner,name,section=='peerDependencies')!=path:continue
                if not isinstance(spec,str):_fail('INVALID_RANGE')
                try:matches=NpmSpec(normalize_npm_range(spec)).match(Version(packages[path]['version']))
                except (ValueError,TypeError,KeyError):_fail('RANGE_UNKNOWN')
                if not matches:_fail('INCOMING_RANGE_MISMATCH')
                rows.append({'owner':owner,'ownerRecordDigest':digest(record),'section':section,'name':name,'range':spec,
                    'peerMeta':record.get('peerDependenciesMeta',{}).get(name) if section=='peerDependencies' else None,'target':path})
    return sorted(rows,key=lambda row:(row['owner'],row['section'],row['name']))

def shared_transition_facts(before,after,path,exact_targets,held_names,protected_names):
    if any(type(lock.get('lockfileVersion')) is not int or lock['lockfileVersion']!=3 for lock in (before,after)):_fail('LOCK_FORMAT_UNSUPPORTED')
    old,new=before['packages'],after['packages'];a,b=old.get(path),new.get(path)
    if not isinstance(a,dict) or not isinstance(b,dict) or a==b:_fail('NOT_EXISTING_CHANGE')
    name=path.split('/node_modules/')[-1].removeprefix('node_modules/')
    if path!='node_modules/'+name or name in held_names or name in exact_targets:_fail('HELD_ROOT_OR_UNSUPPORTED_PATH')
    if name in protected_names:_fail('PROTECTED_INSTANCE')
    if a.get('name',name)!=name or b.get('name',name)!=name or a.get('link') or b.get('link'):_fail('ALIAS_OR_LINK_UNSUPPORTED')
    def artifact(row):
        if any(not isinstance(row.get(k),str) or not row[k] for k in ('version','resolved','integrity')):_fail('ARTIFACT_IDENTITY_MISSING')
        return {'name':name,**{k:row[k] for k in ('version','resolved','integrity')}}
    old_in,new_in=_incoming(old,path),_incoming(new,path)
    held=[row['owner'] for row in old_in if row['owner'] not in {'node_modules/'+n for n in exact_targets}]
    if not held or any(not owner or old.get(owner)!=new.get(owner) for owner in held):_fail('HELD_OWNER_CHANGED_OR_UNKNOWN')
    if any(row['owner'] not in set(held)|{'node_modules/'+n for n in exact_targets} for row in new_in):_fail('NEW_UNREVIEWED_OWNER')
    held_after=[row for row in new_in if row['owner'] in held]
    if old_in!=held_after:_fail('HELD_INCOMING_CHANGED')
    witness=[]
    for row in new_in:
        owner=row['owner'];target=next((n for n in exact_targets if owner=='node_modules/'+n),None)
        if target is None:continue
        if new[owner].get('version')!=exact_targets[target]:_fail('TARGET_VERSION_MISMATCH')
        if not NpmSpec(normalize_npm_range(row['range'])).match(Version(a['version'])):witness.append(row)
    if not witness:_fail('NO_REQUIRED_TARGET_RANGE_WITNESS')
    return {'instance':path,'beforeVersion':a['version'],'afterVersion':b['version'],
        'beforeRecordDigest':digest(a),'afterRecordDigest':digest(b),'beforeArtifactDigest':digest(artifact(a)),
        'afterArtifactDigest':digest(artifact(b)),'beforeIncoming':old_in,'afterIncoming':new_in,
        'heldOwners':sorted(set(held)),'targetRangeWitnesses':witness}

def validate_shared_transitions(before,after,exact_targets,held_names,protected_names,contract):
    if (not isinstance(contract,dict) or set(contract)!={'schemaVersion','beforeLockDigest','afterLockDigest','transitions'}
            or type(contract['schemaVersion']) is not int or contract['schemaVersion']!=1
            or not isinstance(contract['transitions'],list) or not 1<=len(contract['transitions'])<=8):_fail('INVALID_CONTRACT')
    if contract['beforeLockDigest']!=digest(before) or contract['afterLockDigest']!=digest(after):_fail('STALE_GRAPH')
    paths=set()
    for row in contract['transitions']:
        if not isinstance(row,dict) or not isinstance(row.get('instance'),str):_fail('INVALID_ENTRY')
        path=row['instance']
        if path in paths:_fail('DUPLICATE_INSTANCE')
        facts=shared_transition_facts(before,after,path,exact_targets,held_names,protected_names)
        if set(row)!=set(facts)|{'impactCheckId','impactOracleSha256'} or any(row[k]!=v for k,v in facts.items()):_fail('STALE_OR_INCOMPLETE_ENTRY')
        if not isinstance(row['impactCheckId'],str) or not row['impactCheckId']:_fail('IMPACT_CHECK_MISSING')
        if not isinstance(row['impactOracleSha256'],str) or len(row['impactOracleSha256'])!=64 or any(c not in '0123456789abcdef' for c in row['impactOracleSha256']):_fail('IMPACT_ORACLE_INVALID')
        paths.add(path)
    return paths
