"""
Preprocesses 3GPP/ITU ASN.1 schemas to strip constructs that asn1tools
cannot handle (CLASS, information objects, parameterized types), then
compiles the cleaned schemas with asn1tools for BER encoding.
"""

from __future__ import annotations
import re
import os
import glob
import tempfile
import asn1tools
from pathlib import Path


# ---------------------------------------------------------------------------
# Schema preprocessor
# ---------------------------------------------------------------------------

def _remove_balanced(text: str, start: int) -> int:
    """Return index past the closing } matching the { at text[start]."""
    depth = 0
    i = start
    while i < len(text):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(text)


def _remove_parameter_blocks(text: str) -> str:
    """
    Remove PARAMETER <type> clauses from ERROR definitions.
    Handles both inline types and multi-line SEQUENCE/CHOICE blocks.
    Also removes the anonymous value block { field ... } that some schemas
    place directly inside ERROR ::= { { ... } CODE ... }.
    """
    # Remove  PARAMETER <word>  or  PARAMETER SEQUENCE { ... }  or PARAMETER CHOICE { ... }
    result = []
    i = 0
    while i < len(text):
        m = re.search(r'\bPARAMETER\b', text[i:])
        if not m:
            result.append(text[i:])
            break
        pos = i + m.start()
        result.append(text[i:pos])
        after = text[pos + len('PARAMETER'):].lstrip()
        if after.startswith('{'):
            end = _remove_balanced(text, pos + len('PARAMETER') + (len(text) - pos - len('PARAMETER') - len(after)))
            i = end
        else:
            # Skip to end of type token (word)
            m2 = re.match(r'[\w-]+', after)
            if m2:
                i = pos + len('PARAMETER') + (len(text) - pos - len('PARAMETER') - len(after)) + m2.end()
            else:
                i = pos + len('PARAMETER')
        result.append(' ')
    text = ''.join(result)

    # Remove anonymous value blocks inside ERROR ::= { { ... } CODE ... }
    # Walk through and find ERROR ::= { { ... nested ... } CODE ... }
    text = _strip_error_anon_blocks(text)
    return text


def _strip_rose_definitions(text: str) -> str:
    """
    Remove OPERATION ::= { ... } and ERROR ::= { ... } ROSE definitions.
    These use information object notation (CODE, ERRORS, ARGUMENT keywords
    inside the block) which asn1tools cannot parse.
    We keep everything else (the Arg/Res SEQUENCE definitions).
    """
    result = []
    i = 0
    # Match: identifier OPERATION ::= { ... } or identifier ERROR ::= { ... }
    pat = re.compile(r'\b([\w-]+)\s+(OPERATION|ERROR)\s*::=\s*\{')
    while i < len(text):
        m = pat.search(text, i)
        if not m:
            result.append(text[i:])
            break
        result.append(text[i:m.start()])
        # Find matching closing brace
        brace_pos = m.end() - 1  # position of opening {
        end = _remove_balanced(text, brace_pos)
        # Skip trailing newlines
        while end < len(text) and text[end] in '\r\n':
            end += 1
        i = end
    return ''.join(result)


def _strip_error_anon_blocks(text: str) -> str:
    """
    Remove anonymous PARAMETER-like blocks in ERROR definitions:
      ErrorName ERROR ::= { { field ... } CODE ... }
    becomes:
      ErrorName ERROR ::= { CODE ... }
    """
    result = []
    i = 0
    pattern = re.compile(r'\bERROR\s*::=\s*\{')
    while i < len(text):
        m = pattern.search(text, i)
        if not m:
            result.append(text[i:])
            break
        result.append(text[i:m.end()])
        pos = m.end()
        # Now we're inside the ERROR ::= { block. Find the matching }
        # Skip whitespace and check if next non-space char is {
        inner_start = pos
        j = pos
        while j < len(text) and text[j] in ' \t\r\n':
            j += 1
        if j < len(text) and text[j] == '{':
            # This is an anonymous block - skip it using balanced brace counting
            end = _remove_balanced(text, j)
            # Skip over the anonymous block and any trailing whitespace
            result.append('\n')
            i = end
        else:
            i = pos
    return ''.join(result)


def _strip_class_block(text: str) -> str:
    """Remove CLASS definitions (possibly multi-line with WITH SYNTAX)."""
    # CLASS definition: Identifier ::= CLASS { ... } [ WITH SYNTAX ... ]
    out = []
    i = 0
    lines = text.split('\n')
    skip = False
    depth = 0
    for line in lines:
        if re.search(r'::=\s*CLASS\s*\{', line) or (skip and depth > 0):
            skip = True
            depth += line.count('{') - line.count('}')
            if depth <= 0:
                skip = False
                depth = 0
            continue
        # WITH SYNTAX block after CLASS (no braces, just arbitrary text until blank)
        out.append(line)
    return '\n'.join(out)


def preprocess(text: str) -> str:
    """
    Strip / replace ASN.1 constructs that asn1tools cannot handle:
    - CLASS definitions and WITH SYNTAX blocks
    - INSTANCE OF
    - Information object field references (ClassName.&FieldName({Set}))
    - Parameterized SIZE bounds using CLASS fields (SIZE(bound.&min..bound.&max))
    - Parameterized type applications Type{Params}
    - CONTAINING
    - PARAMETER keyword (ROSE extension)
    """
    # Remove CLASS blocks
    text = _strip_class_block(text)

    # Remove WITH SYNTAX blocks
    text = re.sub(r'WITH\s+SYNTAX\s*\{[^}]*(?:\{[^}]*\}[^}]*)*\}', '', text, flags=re.DOTALL)

    # Replace INSTANCE OF X with ANY
    text = re.sub(r'INSTANCE\s+OF\s+[\w-]+', 'ANY', text)

    # Replace SIZE(bound.&min .. bound.&max) style constraints with SIZE(1..255)
    # Must happen BEFORE the generic field ref replacement
    text = re.sub(
        r'SIZE\s*\(\s*[\w-]+\.&[\w-]+\s*\.\.\s*[\w-]+\.&[\w-]+\s*\)',
        'SIZE(1..255)',
        text,
    )
    # SIZE(N..bound.&max) — mixed
    text = re.sub(
        r'SIZE\s*\(\s*(\d+)\s*\.\.\s*[\w-]+\.&[\w-]+\s*\)',
        r'SIZE(\1..255)',
        text,
    )
    # SIZE(bound.&min..N)
    text = re.sub(
        r'SIZE\s*\(\s*[\w-]+\.&[\w-]+\s*\.\.\s*(\d+)\s*\)',
        r'SIZE(1..\1)',
        text,
    )

    # Replace information object field accesses (as types or values):
    # ClassName.&FieldName({Set}) and ClassName.&FieldName
    text = re.sub(r'[\w-]+\.&[\w-]+\s*\(\s*\{[^}]*\}\s*\)', 'ANY', text)
    text = re.sub(r'[\w-]+\.&[\w-]+', 'ANY', text)

    # Remove parameterized actual parameters from type applications
    # e.g. SEQUENCE{SomeParam} → SEQUENCE, but avoid SIZE(...)
    text = re.sub(
        r'(?<!SIZE)\s*\{\s*[\w-]+(?:\s*,\s*[\w-]+)*\s*\}'
        r'(?=\s*(?:::=|OPTIONAL|,|\.\.\.|--|\s*\n))',
        '',
        text,
    )

    # Replace CONTAINING X with ANY
    text = re.sub(r'CONTAINING\s+[\w-]+', 'ANY', text)

    # Remove information object set constraints: ({SomeSet}) / ({Set1|Set2})
    text = re.sub(r'\(\s*\{\s*[\w-]+(?:\s*\|\s*[\w-]+)*\s*\}\s*\)', '', text)

    # Remove PARAMETER keyword (used in ROSE/INAP errortypes): PARAMETER <type>
    # PARAMETER can be followed by a multi-line SEQUENCE/CHOICE block or a type name
    # We must remove the entire value up to but not including CODE or next keyword
    text = _remove_parameter_blocks(text)

    # Remove EXTENSION-SYNTAX (used in some INAP/CAP CLASS definitions)
    text = re.sub(r'EXTENSION-SYNTAX\s+[\w-]+', '', text)

    # Remove parameterized type definitions: TypeName {PARAM : param} ::=  →  TypeName ::=
    text = re.sub(r'([\w-]+)\s*\{\s*[\w-]+(?:\s+:\s+[\w-]+)?\s*\}\s*(::=)', r'\1 \2', text)

    # Remove parameterized type applications in field/member positions: Type {bound}
    # e.g. "CalledPartyNumber {bound}" → "CalledPartyNumber"
    text = re.sub(r'([\w-]+)\s*\{\s*[\w-]+\s*\}(?=\s*(?:OPTIONAL|,|\.\.\.|--|\n|\s+\[))', r'\1', text)

    # Replace EMBEDDED PDV with ANY (not supported by asn1tools)
    text = re.sub(r'\bEMBEDDED\s+PDV\b', 'ANY', text)

    # Replace INTEGER(1..ANY) → INTEGER — remaining after our SIZE substitutions
    text = re.sub(r'\bINTEGER\s*\(\s*(\d+)\s*\.\.\s*ANY\s*\)', 'INTEGER', text)
    text = re.sub(r'\bINTEGER\s*\(\s*ANY\s*\.\.\s*(\d+)\s*\)', 'INTEGER', text)
    text = re.sub(r'\bINTEGER\s*\(\s*ANY\s*\.\.\s*ANY\s*\)', 'INTEGER', text)

    # Remove CRITICALITY / CLASS field assignments in table constraints
    text = re.sub(r'\bCRITICALITY\s+\w+', '', text)

    # Remove IDENTIFIED BY ... (used in CAP-classes.asn extension definitions)
    text = re.sub(r'\bIDENTIFIED\s+BY\s+[\w-]+\s*:\s*\{[^}]*\}', '', text)
    text = re.sub(r'\bIDENTIFIED\s+BY\s+[\w-]+\s*:\s*[\w-]+', '', text)
    text = re.sub(r'\bIDENTIFIED\s+BY\b[^\n]*', '', text)

    # Fix: "SEQUENCE SIZE (n..m) OF Type DEFAULT" → "SEQUENCE SIZE (n..m) OF Type OPTIONAL"
    # DEFAULT without a value after OF is invalid
    text = re.sub(r'(OF\s+[\w-]+)\s+DEFAULT(?!\s+\w)', r'\1 OPTIONAL', text)

    # Strip OPERATION ::= { ... } and ERROR ::= { ... } definitions
    # (ROSE information object notation — we only need the Arg/Res data types)
    text = _strip_rose_definitions(text)

    # Fix parameterized type definitions that survived earlier stripping:
    # TypeName{P1:p1, P2:p2} ::= ... → TypeName ::= ...
    text = re.sub(r'([\w-]+)\s*\{[\w-]+\s*:\s*[\w-]+(?:\s*,\s*[\w-]+\s*:\s*[\w-]+)*\}\s*(::=)', r'\1 \2', text)

    # Fix remaining value assignments for CLASS instances:
    # instanceName CLASSNAME ::= {FIELD value ...} → remove the whole assignment
    text = re.sub(r'^[\w-]+\s+[A-Z][\w-]+\s+::=\s*\{[^}]*\}\s*$', '', text, flags=re.MULTILINE)

    # COMMON-BOUNDS CLASS was stripped; replace its value assignment instances with INTEGER
    text = re.sub(r'\bCOMMON-BOUNDS\b', 'INTEGER', text)

    return text


def compile_schema_dir(schema_dir: str, modules: list[str] | None = None,
                       codec: str = 'ber') -> asn1tools.compiler.CompiledFile:
    """
    Load, preprocess and compile all .asn files from a directory.
    modules: optional list of specific filenames (without path) to include.
    """
    schema_path = Path(schema_dir)
    if modules:
        files = [str(schema_path / m) for m in modules if (schema_path / m).exists()]
    else:
        files = sorted(glob.glob(str(schema_path / '*.asn')))

    cleaned = {}
    tmpdir  = tempfile.mkdtemp(prefix='asn1_clean_')
    try:
        for fpath in files:
            raw  = open(fpath).read()
            proc = preprocess(raw)
            dst  = os.path.join(tmpdir, os.path.basename(fpath))
            with open(dst, 'w') as fh:
                fh.write(proc)
            cleaned[dst] = fpath

        return asn1tools.compile_files(list(cleaned.keys()), codec=codec)
    except Exception:
        raise
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Cached compiled databases
# ---------------------------------------------------------------------------

_CACHE: dict[str, asn1tools.compiler.CompiledFile] = {}

SCHEMAS_ROOT = Path(__file__).parent.parent / 'schemas'

# Full ordered module list (topologically sorted by dependency).
# Stubs are in schemas/stubs/ and provide types missing from downloaded schemas.
ALL_MODULES: list[tuple[str, str]] = [
    # MAP code tables
    ('MobileDomainDefinitions.asn',    'gsm_map/MobileDomainDefinitions.asn'),
    ('MAP-BS-Code.asn',                'gsm_map/MAP-BS-Code.asn'),
    ('MAP-SS-Code.asn',                'gsm_map/MAP-SS-Code.asn'),
    ('MAP-TS-Code.asn',                'gsm_map/MAP-TS-Code.asn'),
    # MAP data types (dependency order)
    ('MAP-ExtensionDataTypes.asn',     'gsm_map/MAP-ExtensionDataTypes.asn'),
    ('MAP-CommonDataTypes.asn',        'gsm_map/MAP-CommonDataTypes.asn'),
    ('MAP-OM-DataTypes.asn',           'gsm_map/MAP-OM-DataTypes.asn'),
    ('MAP-SS-DataTypes.asn',           'gsm_map/MAP-SS-DataTypes.asn'),
    ('MAP-ER-DataTypes.asn',           'gsm_map/MAP-ER-DataTypes.asn'),
    ('MAP-SM-DataTypes.asn',           'gsm_map/MAP-SM-DataTypes.asn'),
    ('MAP-MS-DataTypes.asn',           'gsm_map/MAP-MS-DataTypes.asn'),
    ('MAP-CH-DataTypes.asn',           'gsm_map/MAP-CH-DataTypes.asn'),
    ('MAP-LCS-DataTypes.asn',          'gsm_map/MAP-LCS-DataTypes.asn'),
    ('MAP-GR-DataTypes.asn',           'gsm_map/MAP-GR-DataTypes.asn'),
    # CAP (CAMEL) — stubs provide CS1/CS2 dependencies
    ('CS1-DataTypes.asn',              'stubs/CS1-DataTypes.asn'),
    ('CS2-datatypes.asn',              'stubs/CS2-datatypes.asn'),
    ('CAP-object-identifiers.asn',     'camel/CAP-object-identifiers.asn'),
    ('CAP-operationcodes.asn',         'camel/CAP-operationcodes.asn'),
    ('CAP-errorcodes.asn',             'camel/CAP-errorcodes.asn'),
    ('CAP-datatypes.asn',              'camel/CAP-datatypes.asn'),
    ('CAP-errortypes.asn',             'camel/CAP-errortypes.asn'),
    ('CAP-classes.asn',                'camel/CAP-classes.asn'),
    ('CAP-gsmSSF-gsmSCF-ops-args.asn', 'camel/CAP-gsmSSF-gsmSCF-ops-args.asn'),
    ('CAP-gsmSCF-gsmSRF-ops-args.asn', 'camel/CAP-gsmSCF-gsmSRF-ops-args.asn'),
    ('CAP-gprsSSF-gsmSCF-ops-args.asn','camel/CAP-gprsSSF-gsmSCF-ops-args.asn'),
    ('CAP-SMS-ops-args.asn',           'camel/CAP-SMS-ops-args.asn'),
    ('CAP-GPRS-ReferenceNumber.asn',   'camel/CAP-GPRS-ReferenceNumber.asn'),
    # INAP
    ('IN-object-identifiers.asn',      'inap/IN-object-identifiers.asn'),
    ('IN-operationcodes.asn',          'inap/IN-operationcodes.asn'),
    ('IN-errorcodes.asn',              'inap/IN-errorcodes.asn'),
    ('IN-common-datatypes.asn',        'inap/IN-common-datatypes.asn'),
    ('IN-common-classes.asn',          'inap/IN-common-classes.asn'),
    ('IN-SSF-SCF-datatypes.asn',       'inap/IN-SSF-SCF-datatypes.asn'),
    ('IN-SSF-SCF-ops-args.asn',        'inap/IN-SSF-SCF-ops-args.asn'),
    ('IN-SCF-SRF-datatypes.asn',       'inap/IN-SCF-SRF-datatypes.asn'),
    ('IN-SCF-SRF-ops-args.asn',        'inap/IN-SCF-SRF-ops-args.asn'),
    ('DirectoryAbstractService.asn',   'stubs/DirectoryAbstractService.asn'),
    ('IN-errortypes.asn',              'inap/IN-errortypes.asn'),
]

# Protocol tag for each module file basename
_MODULE_PROTOCOL: dict[str, str] = {}
for _name, _path in ALL_MODULES:
    if _path.startswith('gsm_map'):
        _MODULE_PROTOCOL[_name] = 'map'
    elif _path.startswith('camel') or _path.startswith('stubs/CS'):
        _MODULE_PROTOCOL[_name] = 'cap'
    elif _path.startswith('inap') or _path.startswith('stubs/IN') or _path.startswith('stubs/Dir'):
        _MODULE_PROTOCOL[_name] = 'inap'
    else:
        _MODULE_PROTOCOL[_name] = 'map'


def _compile_best_effort(modules: list[tuple[str, str]],
                         verbose: bool = False) -> asn1tools.compiler.CompiledFile | None:
    """
    Compile a list of (filename, relative-path) modules, skipping any that fail.
    Returns the largest compiled database achievable.
    """
    tmpdir = tempfile.mkdtemp(prefix='asn1_clean_')
    tmps: list[str] = []
    last_good_db = None
    skipped: list[str] = []
    try:
        for name, rel_path in modules:
            src = str(SCHEMAS_ROOT / rel_path)
            if not os.path.exists(src):
                if verbose:
                    print(f"  MISSING {name}")
                continue
            raw  = open(src).read()
            proc = preprocess(raw)
            dst  = os.path.join(tmpdir, name)
            open(dst, 'w').write(proc)
            tmps.append(dst)
            try:
                db = asn1tools.compile_files(tmps[:], codec='ber')
                last_good_db = db
                if verbose:
                    print(f"  OK   {name}")
            except Exception as e:
                if verbose:
                    print(f"  SKIP {name}: {str(e)[:90]}")
                tmps.pop()
                skipped.append(name)
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
    return last_good_db


_CACHE_FILE = Path(__file__).parent.parent / '.schema_cache.pkl'


def get_db(verbose: bool = False, rebuild: bool = False) -> asn1tools.compiler.CompiledFile | None:
    """
    Return the compiled database for all supported protocols.
    Results are cached to .schema_cache.pkl so subsequent calls are instant.
    Pass rebuild=True to force recompilation.
    """
    import pickle, hashlib

    if 'all' in _CACHE:
        return _CACHE['all']

    # Check if any schema file is newer than the cache
    def _cache_valid() -> bool:
        if rebuild or not _CACHE_FILE.exists():
            return False
        cache_mtime = _CACHE_FILE.stat().st_mtime
        for name, rel in ALL_MODULES:
            src = SCHEMAS_ROOT / rel
            if src.exists() and src.stat().st_mtime > cache_mtime:
                return False
        # Also check this file (preprocessor changes)
        if Path(__file__).stat().st_mtime > cache_mtime:
            return False
        return True

    if _cache_valid():
        try:
            with open(_CACHE_FILE, 'rb') as fh:
                _CACHE['all'] = pickle.load(fh)
            if verbose:
                print(f"[schema_loader] Loaded from cache ({len(_CACHE['all'].modules)} modules)")
            return _CACHE['all']
        except Exception:
            pass  # fall through to recompile

    if verbose:
        print("[schema_loader] Compiling schemas (first run, may take ~10s)...")
    db = _compile_best_effort(ALL_MODULES, verbose=verbose)
    _CACHE['all'] = db

    if db:
        try:
            import pickle
            with open(_CACHE_FILE, 'wb') as fh:
                pickle.dump(db, fh, protocol=pickle.HIGHEST_PROTOCOL)
            if verbose:
                print(f"[schema_loader] Saved cache to {_CACHE_FILE}")
        except Exception as e:
            if verbose:
                print(f"[schema_loader] Cache save failed: {e}")
    return db


# Keep legacy per-protocol accessors for backwards compatibility
def get_map_db() -> asn1tools.compiler.CompiledFile | None:
    return get_db()

def get_cap_db() -> asn1tools.compiler.CompiledFile | None:
    return get_db()

def get_inap_db() -> asn1tools.compiler.CompiledFile | None:
    return get_db()


def try_encode(db, type_name: str, value: dict) -> bytes | None:
    """Encode value as type_name using db; return None on failure."""
    if db is None:
        return None
    try:
        return db.encode(type_name, value)
    except Exception:
        return None
