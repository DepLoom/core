"""Read-only proof for one unchanged registry-bundled subtree.

This is not installation, a reusable verification certificate or payload origin
attestation. Members keep their graph obligations and have no invented own SRI.
"""
from pathlib import Path,PurePosixPath
import base64,hashlib,io,json,os,re,tarfile

class NpmBundleEvidenceError(ValueError):pass

def fail(reason):raise NpmBundleEvidenceError('NPM_BUNDLE_'+reason)
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def _object(raw):
 def pairs(items):
  obj={}
  for k,v in items:
   if k in obj:fail('DUPLICATE_JSON')
   obj[k]=v
  return obj
 try:obj=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda x:fail('JSON_CONSTANT'))
 except (ValueError,UnicodeError) as e:raise NpmBundleEvidenceError('NPM_BUNDLE_JSON_UNPROVEN') from e
 if not isinstance(obj,dict):fail('JSON_UNPROVEN')
 return obj

def _safe_path(name):
 if (not isinstance(name,str) or not name or name.startswith('/') or '\\' in name
   or PurePosixPath(name).as_posix()!=name or any(p in ('.','..') for p in name.split('/'))):fail('PATH_UNPROVEN')
 for p in name.split('/'):
  if p.endswith(('.', ' ')) or any(c in p for c in ':*?<>|') or any(ord(c)<32 for c in p):fail('WINDOWS_PATH_AMBIGUOUS')
  if p.split('.')[0].upper() in {'CON','PRN','AUX','NUL',*[f'COM{i}' for i in range(1,10)],*[f'LPT{i}' for i in range(1,10)]}:fail('WINDOWS_PATH_AMBIGUOUS')
 return name

def _name(location):
 if not isinstance(location,str):fail('INSTANCE_PATH_UNPROVEN')
 if re.fullmatch(r'node_modules/(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*(?:/node_modules/(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*)*',location) is None:fail('INSTANCE_PATH_UNPROVEN')
 return location.rsplit('/node_modules/',1)[-1].removeprefix('node_modules/')

def _plain(path):
 for part in [path,*path.parents]:
  if part.is_symlink() or getattr(part,'is_junction',lambda:False)():fail('REPARSE')
 if getattr(path.lstat(),'st_file_attributes',0)&0x400:fail('REPARSE')

def _legacy(lock):
 result={};pending=[('',lock.get('dependencies',{}))]
 while pending:
  base,rows=pending.pop()
  if not isinstance(rows,dict):fail('LEGACY_VIEW_UNPROVEN')
  for name,row in rows.items():
   if not isinstance(name,str) or not isinstance(row,dict):fail('LEGACY_VIEW_UNPROVEN')
   path=(base+'/' if base else '')+'node_modules/'+name;_name(path)
   if path in result or len(result)>=10000:fail('LEGACY_VIEW_UNPROVEN')
   result[path]=row;pending.append((path,row.get('dependencies',{})))
 return result

def read_owner_archive(path,record):
 path=Path(path);_plain(path)
 if not path.is_file() or path.stat().st_size>32*1024*1024:fail('ARCHIVE_SIZE')
 raw=path.read_bytes()
 if record.get('integrity')!='sha512-'+base64.b64encode(hashlib.sha512(raw).digest()).decode():fail('ARCHIVE_SRI_MISMATCH')
 names=set();folded=set();manifests={};files={};total=0
 try:
  with tarfile.open(fileobj=io.BytesIO(raw),mode='r|gz') as archive:
   for m in archive:
    name=m.name[:-1] if m.isdir() and m.name.endswith('/') else m.name;_safe_path(name)
    if not name.startswith('package/') and name!='package':fail('ARCHIVE_ROOT')
    if name=='package' and not m.isdir():fail('ARCHIVE_ROOT')
    if name in names or name.casefold() in folded:fail('ARCHIVE_DUPLICATE_OR_CASE_COLLISION')
    names.add(name);folded.add(name.casefold());total+=m.size
    if len(names)>10000 or total>128*1024*1024 or m.size<0:fail('ARCHIVE_EXPANSION_LIMIT')
    if not (m.isfile() or m.isdir()) or set(m.pax_headers)-{'mtime','atime','ctime'}:fail('ARCHIVE_ENTRY_UNSUPPORTED')
    if m.isfile():
     stream=archive.extractfile(m); h=hashlib.sha256(); remaining=m.size; chunks=[]; is_manifest=(name=='package/package.json' or name.endswith('/package.json'))
     while remaining:
      part=stream.read(min(1024*1024,remaining))
      if not part:fail('ARCHIVE_TRUNCATED_FILE')
      h.update(part); remaining-=len(part)
      if is_manifest:
       if m.size>1024*1024:fail('MANIFEST_SIZE')
       chunks.append(part)
     files[name[len('package/'):]]={'sha256':h.hexdigest(),'bytes':m.size}
    if m.isfile() and (name=='package/package.json' or name.endswith('/package.json') and name.startswith('package/node_modules/')):
     location=name[len('package/'):-len('/package.json')]
     if name!='package/package.json':
      try:_name(location)
      except NpmBundleEvidenceError:continue
     if m.size>1024*1024:fail('MANIFEST_SIZE')
     manifests[name]=_object(b''.join(chunks))
 except (tarfile.TarError,OSError) as e:raise NpmBundleEvidenceError('NPM_BUNDLE_ARCHIVE_UNPROVEN') from e
 owner=manifests.get('package/package.json')
 if owner is None or owner.get('version')!=record.get('version'):fail('OWNER_MANIFEST_MISMATCH')
 return manifests,{'archiveSha256':hashlib.sha256(raw).hexdigest(),'archiveBytes':len(raw),'memberCount':len(names),'files':files}

def subtree_manifest(root):
 root=Path(root);_plain(root)
 if not root.is_dir():fail('SUBTREE_MISSING')
 rows=[];total=0
 for folder,dirs,files in os.walk(root,followlinks=False):
  for name in sorted(dirs+files):
   p=Path(folder)/name;_plain(p);rel=p.relative_to(root).as_posix();_safe_path(rel)
   st=p.lstat()
   if len(rows)>=20000:fail('SUBTREE_LIMIT')
   if p.is_dir():rows.append({'path':rel,'kind':'directory','mode':st.st_mode&0o777,'readonly':bool(getattr(st,'st_file_attributes',0)&1)});continue
   if not p.is_file() or st.st_nlink!=1:fail('SUBTREE_SPECIAL_OR_HARDLINK')
   total+=st.st_size
   if total>128*1024*1024:fail('SUBTREE_LIMIT')
   b=p.read_bytes()
   if len(b)!=st.st_size or p.stat().st_mtime_ns!=st.st_mtime_ns:fail('SUBTREE_CHANGED_DURING_READ')
   rows.append({'path':rel,'kind':'file','bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'readonly':bool(getattr(st,'st_file_attributes',0)&1),'mode':st.st_mode&0o777})
 return {'entries':sorted(rows,key=lambda r:r['path']),'bytes':total}

def prove_unchanged_owner(before,after,owner,archive_path,baseline_project,*,ordinary_nested_archives=None):
 """Inspect CURRENT pinned baseline; never retroactively claim a historic proof."""
 _name(owner)
 if any(type(lock.get('lockfileVersion')) is not int or lock['lockfileVersion']!=2 for lock in (before,after)):fail('V2_REQUIRED')
 if not all(isinstance(lock,dict) and isinstance(lock.get('packages'),dict) and len(lock['packages'])<=10001 and all(isinstance(k,str) and isinstance(v,dict) for k,v in lock['packages'].items()) for lock in (before,after)):fail('GRAPH_UNPROVEN')
 old=before['packages'];new=after['packages'];a=old.get(owner);b=new.get(owner)
 if not isinstance(a,dict) or a!=b or a.get('inBundle') or a.get('link'):fail('OWNER_CHANGED_OR_UNSUPPORTED')
 if not a.get('bundleDependencies') and not a.get('bundledDependencies'):fail('OWNER_NOT_BUNDLED')
 from urllib.parse import urlsplit
 url=urlsplit(a.get('resolved',''))
 if url.scheme!='https' or not url.hostname or url.username or url.password or url.query or url.fragment:fail('OWNER_ORIGIN_UNPROVEN')
 groups=[]
 for graph in (old,new):
  group={p:r for p,r in graph.items() if p.startswith(owner+'/node_modules/') and r.get('inBundle') is True}
  if not group or len(group)>512:fail('MEMBER_SET_UNPROVEN')
  groups.append(group)
 if groups[0]!=groups[1]:fail('MEMBER_RECORDS_CHANGED')
 members=groups[0];legacy=[_legacy(lock) for lock in (before,after)]
 ordinary_nested_archives={} if ordinary_nested_archives is None else ordinary_nested_archives
 if not isinstance(ordinary_nested_archives,dict) or len(ordinary_nested_archives)>32:fail('ORDINARY_NESTED_RULES')
 ordinary={p:r for p,r in old.items() if p.startswith(owner+'/node_modules/') and p not in members}
 other={p:r for p,r in new.items() if p.startswith(owner+'/node_modules/') and p not in members}
 if ordinary!=other:fail('ORDINARY_NESTED_CHANGED')
 if set(ordinary_nested_archives)!=set(ordinary):fail('ORDINARY_NESTED_ARCHIVES_REQUIRED')
 for graph,view in zip((old,new),legacy):
  for path in [owner,*members,*ordinary]:
   record=graph[path];other=view.get(path)
   if not isinstance(other,dict) or record.get('version')!=other.get('version'):fail('LOCK_VIEW_MISMATCH')
   if bool(record.get('inBundle')) != bool(other.get('bundled')):fail('LOCK_VIEW_MISMATCH')
   for field in ('resolved','integrity'):
    if record.get(field)!=other.get(field):fail('LOCK_VIEW_MISMATCH')
   requirements={**record.get('dependencies',{}),**record.get('optionalDependencies',{})}
   if requirements!=other.get('requires',{}):fail('LOCK_VIEW_MISMATCH')
 manifests,archive=read_owner_archive(archive_path,a)
 if manifests['package/package.json'].get('name')!=_name(owner):fail('OWNER_NAME_MISMATCH')
 expected={'package/'+p[len(owner)+1:]+'/package.json':p for p in members}
 if set(manifests)!={'package/package.json',*expected}:fail('ARCHIVE_MEMBER_SET_MISMATCH')
 physical={}
 for archive_name,path in {'package/package.json':owner,**expected}.items():
  m=manifests[archive_name];row=new[path]
  if m.get('name')!=_name(path) or m.get('version')!=row.get('version'):fail('MEMBER_IDENTITY_MISMATCH')
  for field in ('dependencies','optionalDependencies','peerDependencies','peerDependenciesMeta','engines','os','cpu','libc','bundleDependencies','bundledDependencies'):
   if field in row and row[field]!=m.get(field):fail('MEMBER_METADATA_MISMATCH')
  f=Path(baseline_project)/path/'package.json';_plain(f)
  actual=_object(f.read_bytes())
  if actual!=m:fail('BASELINE_ARCHIVE_MANIFEST_MISMATCH')
  physical[path]=digest(m)
 ordinary_proofs={}
 for path,record in ordinary.items():
  _name(path)
  if record.get('inBundle') or record.get('link') or record.get('bundleDependencies') or record.get('bundledDependencies'):fail('ORDINARY_NESTED_UNSUPPORTED')
  u=urlsplit(record.get('resolved',''))
  if u.scheme!='https' or not u.hostname or u.username or u.password or u.query or u.fragment:fail('ORDINARY_NESTED_ORIGIN')
  ms,artifact=read_owner_archive(ordinary_nested_archives[path],record)
  if set(ms)!={'package/package.json'}:fail('ORDINARY_NESTED_BUNDLE_UNSUPPORTED')
  m=ms['package/package.json']
  if m.get('name')!=_name(path) or m.get('version')!=record.get('version'):fail('ORDINARY_NESTED_IDENTITY')
  for key in ('dependencies','optionalDependencies','peerDependencies','peerDependenciesMeta','engines','os','cpu','libc'):
   if key in record and record[key]!=m.get(key):fail('ORDINARY_NESTED_METADATA')
  f=Path(baseline_project)/path/'package.json';_plain(f)
  if _object(f.read_bytes())!=m:fail('ORDINARY_NESTED_PHYSICAL_MANIFEST')
  physical[path]=digest(m);prefix=path[len(owner)+1:]+'/'
  for name,value in artifact['files'].items():
   target=prefix+name
   if target in archive['files']:fail('ORDINARY_NESTED_ARCHIVE_OVERLAP')
   archive['files'][target]=value
  ordinary_proofs[path]={'lockRecordDigest':digest(record),'archiveSha256':artifact['archiveSha256']}
 payload=subtree_manifest(Path(baseline_project)/owner)
 actual_files={r['path']:r for r in payload['entries'] if r['kind']=='file'}
 for path,expected_file in archive['files'].items():
  actual_file=actual_files.get(path)
  if actual_file is None or any(actual_file[k]!=expected_file[k] for k in ('sha256','bytes')):fail('BASELINE_ARCHIVE_PAYLOAD_MISMATCH')
 # Generated npm launch wrappers have no archive origin assertion. Keep every
 # byte in the baseline preservation manifest; do not omit them from later checks.
 extras=sorted(set(actual_files)-set(archive['files']))
 if any('/.bin/' not in '/'+p for p in extras):fail('BASELINE_UNEXPECTED_PAYLOAD_FILE')
 archive['generatedBinPaths']=extras
 return {'schemaVersion':1,'kind':'UNCHANGED_BUNDLED_OWNER_PROOF_V1','owner':owner,
   'ownerRecordDigest':digest(a),'memberRecordDigests':{p:digest(r) for p,r in sorted(members.items())},
   'archive':archive,'ordinaryNestedProofs':ordinary_proofs,'manifestDigests':physical,'baselineSubtree':payload,
   'baselineSubtreeDigest':digest(payload),'memberCount':len(members),
   'authority':'READ_ONLY_SCOPE_PREFLIGHT','physicalNodeEdges':'NOT_VERIFIED','installation':'NOT_VERIFIED',
   'fullAcceptance':False}


def validate_bundle_rules_shape(rules):
 if (not isinstance(rules,dict) or set(rules)!={'schemaVersion','kind','baselineProjectPath','baselineLockSha256','owners'}
   or type(rules['schemaVersion']) is not int or rules['schemaVersion']!=1
   or rules['kind']!='UNCHANGED_NPM_V2_BUNDLED_OWNER_RULES_V1'
   or not isinstance(rules['baselineProjectPath'],str) or not Path(rules['baselineProjectPath']).is_absolute()
   or not isinstance(rules['baselineLockSha256'],str) or re.fullmatch('[0-9a-f]{64}',rules['baselineLockSha256']) is None
   or not isinstance(rules['owners'],list) or len(rules['owners'])!=1):fail('RULE_SCHEMA')
 row=rules['owners'][0]
 if (not isinstance(row,dict) or set(row)!={'instance','archivePath','baselineSubtreeDigest','ordinaryNestedArchives'}
   or not isinstance(row['archivePath'],str) or not Path(row['archivePath']).is_absolute()
   or not isinstance(row['baselineSubtreeDigest'],str) or re.fullmatch('[0-9a-f]{64}',row['baselineSubtreeDigest']) is None
   or not isinstance(row['ordinaryNestedArchives'],dict)
   or any(not isinstance(k,str) or not isinstance(v,str) or not Path(v).is_absolute() for k,v in row['ordinaryNestedArchives'].items())):fail('OWNER_RULE_SCHEMA')
 _name(row['instance'])
 return rules


def compile_bundle_rules(before,after,rules,baseline_lock_bytes):
 validate_bundle_rules_shape(rules)
 baseline=Path(rules['baselineProjectPath']);_plain(baseline)
 actual=(baseline/'package-lock.json').read_bytes()
 if actual!=baseline_lock_bytes or hashlib.sha256(actual).hexdigest()!=rules['baselineLockSha256']:fail('BASELINE_LOCK_UNBOUND')
 result={}
 for row in rules['owners']:
  p=prove_unchanged_owner(before,after,row['instance'],row['archivePath'],baseline,
     ordinary_nested_archives=row['ordinaryNestedArchives'])
  if p['baselineSubtreeDigest']!=row['baselineSubtreeDigest']:fail('PINNED_BASELINE_SUBTREE_CHANGED')
  result[row['instance']]=p
 return result


def compare_installed_owner(project,proof):
 """Byte/meaningful-metadata preservation only; no implicit Node edge proof."""
 if (not isinstance(proof,dict) or proof.get('kind')!='UNCHANGED_BUNDLED_OWNER_PROOF_V1'
     or proof.get('authority')!='READ_ONLY_SCOPE_PREFLIGHT' or proof.get('fullAcceptance') is not False
     or proof.get('baselineSubtreeDigest')!=digest(proof.get('baselineSubtree'))):fail('PROOF_UNBOUND')
 owner=proof.get('owner');_name(owner)
 current=subtree_manifest(Path(project)/owner)
 if current!=proof['baselineSubtree']:fail('INSTALLED_SUBTREE_CHANGED')
 for path,wanted in proof['manifestDigests'].items():
  f=Path(project)/path/'package.json';_plain(f)
  if digest(_object(f.read_bytes()))!=wanted:fail('INSTALLED_MANIFEST_CHANGED')
 return {'status':'UNCHANGED_BUNDLED_SUBTREE_OBSERVED','owner':owner,
  'memberCount':proof['memberCount'],'subtreeDigest':digest(current),
  'physicalNodeEdges':'NOT_VERIFIED','fullAcceptance':False}
