"""Explicit standalone build/test outputs, separate from authored source.

Opt-in only. A source exclusion is never a verification receipt. The current
workspace verifier requires absent roots before execution, the original recipe,
quiescent supervised commands, complete bounded inventories and immutable output
observations afterwards. Boundary observations do not attest arbitrary hostile
concurrent writers or per-file writer provenance.
"""
from __future__ import annotations
import hashlib,json,os,re,stat,time
from pathlib import Path,PurePosixPath

PROFILE='standalone-js-cli-output-v1'
KIND='STANDALONE_JS_CLI_OUTPUT_V1'
ROOTS=('dist','.tap')
MAX_FILE_BYTES=8*1024*1024
MAX_TOTAL_BYTES=64*1024*1024
MAX_PROCESS_FILES=128
_UUID=re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json\Z')
_SHA=re.compile(r'[0-9a-f]{64}\Z')

class GeneratedOutputError(RuntimeError):pass

def _fail(code):raise GeneratedOutputError('GENERATED_OUTPUT_'+code)
def _digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def _budget(deadline):
    if not isinstance(deadline,(int,float)) or isinstance(deadline,bool) or not time.time()<deadline:_fail('DEADLINE')
def _plain(path,directory):
    info=path.lstat()
    if (stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400
            or (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))
            or not directory and info.st_nlink!=1):_fail('LINK_OR_TYPE')
    return info

def _path(value,prefix,suffix):
    if (not isinstance(value,str) or not value or len(value)>256 or '\\' in value or ':' in value
            or '\x00' in value or value!=PurePosixPath(value).as_posix()
            or any(p in ('.','..') or p.endswith(('.',' ')) for p in value.split('/'))
            or not value.startswith(prefix) or not value.endswith(suffix)):_fail('SPEC_PATH')
    return value

def validate_spec(spec,project,commands):
    keys={'schemaVersion','kind','buildFiles','testFiles','emptyDirectories','buildScriptSha256','testScriptSha256','perfScriptSha256'}
    if (not isinstance(spec,dict) or set(spec)!=keys or type(spec['schemaVersion']) is not int
            or spec['schemaVersion']!=1 or spec['kind']!=KIND):_fail('SPEC')
    for key in ('buildScriptSha256','testScriptSha256','perfScriptSha256'):
        if not isinstance(spec[key],str) or _SHA.fullmatch(spec[key]) is None:_fail('SPEC_HASH')
    files=spec['buildFiles'];tests=spec['testFiles']
    if spec['emptyDirectories'] not in ([],['.tap/fixtures']):_fail('EMPTY_DIRECTORY_SPEC')
    if (not isinstance(files,list) or not 1<=len(files)<=128 or any(not isinstance(n,str) for n in files) or files!=sorted(set(files))
            or not isinstance(tests,list) or not 1<=len(tests)<=128 or any(not isinstance(n,str) for n in tests) or tests!=sorted(set(tests))):_fail('SPEC_FILES')
    for name in files:
        _path(name,'dist/','')
        if len(PurePosixPath(name).parts)!=2:_fail('SPEC_PATH')
    for name in tests:
        _path(name,'tests/','.js')
        if len(PurePosixPath(name).parts)!=2:_fail('SPEC_PATH')
    if len({x.casefold() for x in files+tests})!=len(files)+len(tests):_fail('SPEC_COLLISION')
    if (not isinstance(commands,(list,tuple)) or list(commands[:2])!=['npm test','npm run test:perf']
            or any(c in ('npm test','npm run test:perf') for c in commands[2:])):_fail('COMMAND_RECIPE')
    project=Path(project)
    actual=sorted(p.relative_to(project).as_posix() for p in (project/'tests').rglob('*.js'))
    if actual!=tests:_fail('TEST_SET')
    for name in tests:_plain(project/name,False)
    _plain(project/'scripts/build.js',False);_plain(project/'package.json',False)
    package=json.loads((project/'package.json').read_bytes());scripts=package.get('scripts',{})
    expected={'buildScriptSha256':hashlib.sha256((project/'scripts/build.js').read_bytes()).hexdigest(),
        'testScriptSha256':hashlib.sha256(str(scripts.get('test','')).encode()).hexdigest(),
        'perfScriptSha256':hashlib.sha256(str(scripts.get('test:perf','')).encode()).hexdigest()}
    if any(spec[k]!=v for k,v in expected.items()):_fail('SOURCE_RECIPE')
    return _digest(spec)

def require_absent(project,*,deadline):
    _budget(deadline);project=Path(project)
    for name in ROOTS:
        if os.path.lexists(project/name):_fail('PREEXISTING_ROOT')

def output_inventory(project,spec,*,deadline):
    """Complete bounded no-follow output walk; never reads processinfo JSON."""
    _budget(deadline);project=Path(project);rows=[];seen=set();total=0;process=0
    required=set(spec['buildFiles'])|{'.tap/test-results/'+name+'.tap' for name in spec['testFiles']}
    allowed_dirs={'dist','.tap','.tap/processinfo','.tap/test-results','.tap/test-results/tests'}|set(spec['emptyDirectories'])
    def visit(path,name):
        nonlocal total,process
        _budget(deadline)
        if name.casefold() in seen:_fail('CASE_COLLISION')
        seen.add(name.casefold())
        info=path.lstat();directory=stat.S_ISDIR(info.st_mode);_plain(path,directory)
        row={'relativePath':name,'type':'directory' if directory else 'file','device':str(info.st_dev),'inode':str(info.st_ino)}
        if directory:
            if name not in allowed_dirs:_fail('UNEXPECTED_DIRECTORY')
            entries=sorted(path.iterdir(),key=lambda p:p.name)
            if name in spec['emptyDirectories'] and entries:_fail('FIXTURE_CLEANUP_INCOMPLETE')
            if len(entries)>256:_fail('COUNT_CAP')
            rows.append(row)
            for child in entries:visit(child,name+'/'+child.name)
            after=path.lstat()
            if (info.st_dev,info.st_ino)!=(after.st_dev,after.st_ino):_fail('UNSTABLE_DIRECTORY')
        else:
            if name not in required:
                if name.startswith('.tap/processinfo/') and _UUID.fullmatch(name[len('.tap/processinfo/'):]):process+=1
                else:_fail('UNEXPECTED_FILE')
            if info.st_size>MAX_FILE_BYTES:_fail('SIZE_CAP')
            total+=info.st_size
            if total>MAX_TOTAL_BYTES or len(rows)>512 or process>MAX_PROCESS_FILES:_fail('SIZE_OR_COUNT_CAP')
            digest=hashlib.sha256();count=0
            with path.open('rb') as stream:
                opened=os.fstat(stream.fileno())
                if (opened.st_dev,opened.st_ino)!=(info.st_dev,info.st_ino):_fail('PATH_CHANGED')
                for chunk in iter(lambda:stream.read(65536),b''):
                    _budget(deadline);count+=len(chunk)
                    if count>MAX_FILE_BYTES:_fail('SIZE_CAP')
                    digest.update(chunk)
                after=os.fstat(stream.fileno())
            final=_plain(path,False)
            stamp=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_nlink)
            if stamp(info)!=stamp(opened) or stamp(info)!=stamp(after) or stamp(info)!=stamp(final) or count!=info.st_size:_fail('UNSTABLE_FILE')
            row.update(size=count,sha256=digest.hexdigest());rows.append(row)
    for root in ROOTS:visit(project/root,root)
    files={r['relativePath'] for r in rows if r['type']=='file'}
    directories={r['relativePath'] for r in rows if r['type']=='directory'}
    if not required.issubset(files) or not set(spec['emptyDirectories']).issubset(directories) or not 1<=process<=MAX_PROCESS_FILES:_fail('MISSING_FILES')
    return rows

def capture_receipt(project,spec,*,deadline,binding):
    needed={'sourceSnapshotKey','profileDigest','invocationId','dependencyPlanDigest','approvedLockSha256','environmentDigest','toolchain','buildCommandDigest'}
    if not isinstance(binding,dict) or set(binding)!=needed:_fail('BINDING')
    first=output_inventory(project,spec,deadline=deadline)
    if first!=output_inventory(project,spec,deadline=deadline):_fail('UNSTABLE_INVENTORY')
    return {'schemaVersion':1,'kind':KIND,'recipeDigest':_digest(spec),'binding':binding,
        'inventory':first,'inventoryDigest':_digest(first),'authority':'NON_REUSABLE_BOUNDARY_OBSERVATION',
        'writerProvenanceVerified':False,'arbitraryConcurrentFilesystemClosureVerified':False}

def receipt_current(project,spec,receipt,*,deadline,binding):
    try:
        if (not isinstance(receipt,dict) or set(receipt)!={'schemaVersion','kind','recipeDigest','binding','inventory','inventoryDigest','authority','writerProvenanceVerified','arbitraryConcurrentFilesystemClosureVerified'}
                or type(receipt['schemaVersion']) is not int or receipt['schemaVersion']!=1 or receipt['kind']!=KIND
                or receipt['recipeDigest']!=_digest(spec) or receipt['inventoryDigest']!=_digest(receipt['inventory'])
                or receipt['authority']!='NON_REUSABLE_BOUNDARY_OBSERVATION'
                or receipt['writerProvenanceVerified'] is not False or receipt['arbitraryConcurrentFilesystemClosureVerified'] is not False
                or not isinstance(binding,dict) or receipt['binding']!=binding):return False
        return output_inventory(project,spec,deadline=deadline)==receipt['inventory']
    except (GeneratedOutputError,OSError,KeyError,TypeError,ValueError):return False


def validate_input_only_materialization(snapshot, original_project, contract, *, deadline, delivered_project=None):
    """Authorize source transport only, never a source/output verification proof.

    Both live/sealed inputs and the delivered copy must have absent output roots.
    Generic verification still rejects this policy; only the explicit current
    workspace verifier can execute and bind fresh generated output receipts.
    """
    from source_snapshot import SourceInputPolicy,SourceCaptureError
    policy=snapshot.input_policy
    if (not isinstance(contract,dict) or set(contract)!={'spec','commands'}
            or policy!=SourceInputPolicy(generated_output_profile=PROFILE)
            or snapshot.project_relative!=Path('.')
            or Path(original_project).resolve()!=snapshot.original_project_path.resolve()
            or snapshot.capture_root.resolve()!=snapshot.original_project_path.resolve()):
        raise SourceCaptureError('SOURCE_GENERATED_OUTPUT_TRANSPORT_CONTRACT_INVALID')
    recipe=None
    for project in (Path(original_project),snapshot.project_path,*(() if delivered_project is None else (Path(delivered_project),))):
        require_absent(project,deadline=deadline)
        current=validate_spec(contract['spec'],project,contract['commands'])
        if recipe is not None and current!=recipe:_fail('TRANSPORT_RECIPE_CHANGED')
        recipe=current
    return {'scope':'SOURCE_INPUT_TRANSPORT_ONLY','verification':'NOT_VERIFIED','recipeDigest':recipe}
