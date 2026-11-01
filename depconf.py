#!/usr/bin/env python3
"""depconf — find dependency-confusion exposure in a set of GitHub repositories.

Premise: a public repository that depends on a package name which does not
exist in the public registry is a hijack opportunity. Anyone can register the
name, and any build that resolves from the public registry — directly, or by
falling back when an internal mirror misses — will fetch the attacker's code.

This only ever *reads*. It asks the public registry whether a name is taken.
It never registers anything and never touches credentials.

Output is a candidate list. A name being unregistered is necessary but not
sufficient: the dependency may be vendored, resolved from a private index that
never consults the public one, or simply dead code. Each hit needs a human to
decide whether a real build would reach for it.

Compared to the established tools in this space (confused, dependency-
combobulator, confusion-hunter): those are more mature, but share two gaps
this version closes, because they matter for false-positive rate and for
monorepo coverage, which is most of what a real target's repo set looks like:

  1. SEVERITY FOR SCOPED NPM PACKAGES. A missing `@acme/internal-tool` is NOT
     automatically hijackable -- only if the `@acme` scope itself is unclaimed
     on the public registry. If the org already exists there (even just for
     one public package), nobody can publish under that scope without
     compromising the org, so the specific missing package is not a public
     hijack target. The original version of this tool, and a naive reading of
     "confused"-style output, both treat every missing scoped name as
     equally hijackable, which overstates severity for the common case of a
     company that *does* have a public npm presence but keeps some packages
     private. This version checks scope ownership separately and downgrades
     accordingly.
  2. NESTED MANIFESTS. The original only read root-level package.json /
     requirements.txt via the GitHub contents API. Most real dependency-
     confusion exposure lives in monorepos, where the actual build manifest
     is two or three directories deep. This version walks the full repo tree.
"""
import json, re, subprocess, sys, time, urllib.request, urllib.error, urllib.parse, argparse, base64
from concurrent.futures import ThreadPoolExecutor

UA = {"User-Agent": "depconf-research/2.0"}

# ---------------------------------------------------------------- registries
def _head(url, retries=2):
    """GET with a couple of retries on anything that isn't a clean 404 --
    the original version returned 'unknown' on the first rate-limit hit,
    which on a few-hundred-dependency run turned a meaningful fraction of
    results into noise instead of answers. A 404 is definitive and returned
    immediately; everything else gets one backoff before giving up."""
    req = urllib.request.Request(url, headers=UA, method="GET")
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status == 200
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return False
            if e.code == 429 and attempt < retries:
                time.sleep(2 * (attempt + 1))
                continue
            return None
        except Exception:
            if attempt < retries:
                time.sleep(1)
                continue
            return None
    return None

def npm_exists(name):
    return _head(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@/')}")

def npm_scope_exists(scope):
    """Is the @scope itself registered to anyone (does at least one public
    package exist under it)? An empty result means the scope has never been
    claimed on public npm -- the classic, worst-case dependency-confusion
    precondition (register the org, publish anything under it). A non-empty
    result means someone legitimate already owns the scope, which *lowers*
    severity for any other missing package under it, since hijacking now
    requires compromising that org rather than just registering a free name.

    IMPORTANT: npm's search API does NOT support a `scope:` query qualifier
    the way its own docs imply -- `text=scope:babel` returns 0 results for
    @babel, one of the most-owned scopes on the registry, and returns
    thousands of irrelevant free-text matches for a scope that was made up
    for this file's own test run. That was caught by testing this function
    against a known-real scope and a known-fake one before shipping it, not
    by reading documentation; both directions were wrong on the first
    attempt. The fix: search for the literal "@scope" substring as free
    text, then verify in code that at least one returned package name
    actually starts with "@scope/" -- the search ranking can surface
    unrelated noise, but a real prefix match on the name itself can't lie.
    """
    url = f"https://registry.npmjs.org/-/v1/search?text={urllib.parse.quote('@' + scope)}&size=20"
    req = urllib.request.Request(url, headers=UA, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            d = json.loads(r.read().decode())
            prefix = f"@{scope}/"
            return any(o.get("package", {}).get("name", "").startswith(prefix)
                       for o in d.get("objects", []))
    except Exception:
        return None  # inconclusive -- don't claim a severity we can't support

def pypi_exists(name):
    return _head(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")

def go_exists(module):
    # proxy.golang.org answers for any module path with case-encoding
    # (uppercase -> !lowercase), which only matters for mixed-case module
    # paths; most real Go module paths are already lowercase.
    enc = re.sub(r'[A-Z]', lambda m: '!' + m.group(0).lower(), module)
    return _head(f"https://proxy.golang.org/{urllib.parse.quote(enc, safe='/.@')}/@latest")

def packagist_exists(name):
    return _head(f"https://repo.packagist.org/p2/{urllib.parse.quote(name)}.json")

# ---------------------------------------------------------------- extraction
SCOPED = re.compile(r'^@([\w.-]+)/([\w.-]+)$')
PLAIN  = re.compile(r'^[\w.-]+$')

def _pep503(name):
    """PyPI treats '-', '_' and '.' as equivalent and is case-insensitive
    (PEP 503). Without normalizing, 'my_pkg' and 'my-pkg' were previously
    treated as two distinct dependencies -- doubling registry calls for the
    same real-world name, and, worse, able to disagree with each other if
    one direction 404s due to a transient error while the other doesn't."""
    return re.sub(r'[-_.]+', '-', name).lower()

def from_package_json(txt):
    out = set()
    try:
        d = json.loads(txt)
    except Exception:
        return out
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name, spec in (d.get(key) or {}).items():
            if not isinstance(spec, str):
                continue
            # skip anything not resolved from the registry
            if any(spec.startswith(p) for p in ("file:", "link:", "git", "http", "workspace:", "portal:")):
                continue
            if SCOPED.match(name) or PLAIN.match(name):
                out.add(("npm", name))
    return out

REQ_LINE = re.compile(r'^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[<>=!~\[;].*)?$')

def from_requirements(txt):
    out = set()
    for line in txt.splitlines():
        line = line.split('#')[0].strip()
        if not line or line.startswith('-') or '://' in line or line.startswith('.'):
            continue
        m = REQ_LINE.match(line)
        if m:
            out.add(("pypi", _pep503(m.group(1))))
    return out

def from_pyproject(txt):
    """PEP 621 [project.dependencies] and the older Poetry
    [tool.poetry.dependencies] table. Deliberately not a real TOML parser
    (avoids a dependency) -- just enough line-shape matching to pull names
    out of the two common forms, same spirit as the regex-based .py scanner
    this ships alongside."""
    out = set()
    in_deps = False
    in_poetry_deps = False
    for raw in txt.splitlines():
        line = raw.strip()
        if line.startswith('dependencies') and '=' in line and '[' in line:
            in_deps = True
            continue
        if line.startswith('[tool.poetry.dependencies]'):
            in_poetry_deps = True
            continue
        if line.startswith('[') :
            in_deps = False
            in_poetry_deps = False
            continue
        if in_deps:
            m = re.match(r'"([A-Za-z0-9][A-Za-z0-9._-]*)', line)
            if m:
                out.add(("pypi", _pep503(m.group(1))))
        if in_poetry_deps:
            m = re.match(r'([A-Za-z0-9][A-Za-z0-9._-]*)\s*=', line)
            if m and m.group(1).lower() != 'python':
                out.add(("pypi", _pep503(m.group(1))))
    return out

def from_gomod(txt):
    out = set()
    in_require = False
    for raw in txt.splitlines():
        line = raw.split('//')[0].strip()
        if line.startswith('require') and '(' in line:
            in_require = True
            continue
        if in_require and line == ')':
            in_require = False
            continue
        m = None
        if in_require:
            m = re.match(r'([^\s]+)\s+v[\d.]', line)
        elif line.startswith('require '):
            m = re.match(r'require\s+([^\s]+)\s+v[\d.]', line)
        if m:
            mod = m.group(1)
            # stdlib-adjacent / no-dot module paths can't be registry-hijacked
            # the same way (no host to squat), so skip them -- avoids noise.
            if '.' in mod.split('/')[0]:
                out.add(("go", mod))
    return out

def from_composer(txt):
    out = set()
    try:
        d = json.loads(txt)
    except Exception:
        return out
    for key in ("require", "require-dev"):
        for name in (d.get(key) or {}):
            if name == "php" or name.startswith("ext-"):
                continue
            if re.match(r'^[\w.-]+/[\w.-]+$', name):
                out.add(("packagist", name))
    return out

MANIFESTS = {
    "package.json": from_package_json,
    "requirements.txt": from_requirements,
    "pyproject.toml": from_pyproject,
    "go.mod": from_gomod,
    "composer.json": from_composer,
}

# ---------------------------------------------------------------- github
def gh_json(path):
    try:
        out = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            return None
        return json.loads(out.stdout)
    except Exception:
        return None

def repo_manifest_paths(repo):
    """Full-tree listing instead of a fixed set of root-level filenames --
    the previous version only ever checked repos/{repo}/contents/{fname} at
    the root, so any manifest inside a monorepo subdirectory (packages/*,
    services/*, apps/*...) was invisible. The git trees API in recursive
    mode returns the whole path list in one call per repo, which is both
    more complete and cheaper than probing N candidate paths."""
    d = gh_json(f"repos/{repo}/git/trees/HEAD?recursive=1")
    if not isinstance(d, dict):
        return []
    names = set(MANIFESTS)
    out = []
    for entry in d.get("tree", []):
        if entry.get("type") != "blob":
            continue
        p = entry.get("path", "")
        base = p.rsplit('/', 1)[-1]
        if base in names and '/node_modules/' not in p and '/vendor/' not in p:
            out.append(p)
    return out

def fetch_manifest(repo, path):
    d = gh_json(f"repos/{repo}/contents/{path}")
    if not (isinstance(d, dict) and d.get("content")):
        return set()
    try:
        txt = base64.b64decode(d["content"]).decode("utf-8", "replace")
    except Exception:
        return set()
    parser = MANIFESTS[path.rsplit('/', 1)[-1]]
    return parser(txt)

def repo_manifests(repo):
    found = {}
    for path in repo_manifest_paths(repo):
        deps = fetch_manifest(repo, path)
        if deps:
            found[path] = deps
    return found

# ---------------------------------------------------------------- severity
def classify_npm(name, scope_cache):
    """Returns (exists, severity) for a missing npm dependency. severity is
    only meaningful when exists is False."""
    m = SCOPED.match(name)
    if not m:
        ex = npm_exists(name)
        return ex, (None if ex else 'high')   # unscoped: a free name is a free hijack
    scope, pkg = m.groups()
    ex = npm_exists(name)
    if ex is not False:
        return ex, None
    if scope not in scope_cache:
        scope_cache[scope] = npm_scope_exists(scope)
    scope_owned = scope_cache[scope]
    if scope_owned is True:
        return False, 'low'    # scope taken by someone -- needs org compromise, not a public squat
    if scope_owned is False:
        return False, 'high'   # scope itself unclaimed -- the classic case
    return False, 'unknown'    # couldn't resolve scope ownership

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repolist", help="file with one owner/repo per line")
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text (for CI)")
    a = ap.parse_args()

    repos = [l.strip() for l in open(a.repolist) if l.strip()]
    print(f"{len(repos)} repos", file=sys.stderr)

    seen = {}          # (eco, name) -> [repo:path, ...]
    for i, repo in enumerate(repos, 1):
        for path, deps in repo_manifests(repo).items():
            for eco, name in deps:
                seen.setdefault((eco, name), []).append(f"{repo}:{path}")
        if i % 25 == 0:
            print(f"  {i}/{len(repos)} repos, {len(seen)} distinct deps", file=sys.stderr)

    print(f"{len(seen)} distinct dependencies; checking the registries", file=sys.stderr)

    scope_cache = {}
    def check(item):
        (eco, name), where = item
        if eco == "npm":
            ok, sev = classify_npm(name, scope_cache)
        else:
            fn = {"pypi": pypi_exists, "go": go_exists, "packagist": packagist_exists}[eco]
            ok, sev = fn(name), 'high'
        return (eco, name, ok, sev, where)

    results = []
    with ThreadPoolExecutor(max_workers=a.jobs) as ex:
        for r in ex.map(check, seen.items()):
            results.append(r)

    missing = [r for r in results if r[2] is False]
    unknown = [r for r in results if r[2] is None]
    present = len(results) - len(missing) - len(unknown)

    if a.json:
        out = [{"ecosystem": eco, "name": name, "severity": sev, "found_in": where}
               for eco, name, _, sev, where in missing]
        print(json.dumps({"hijackable": out, "unresolved": len(unknown), "present": present}, indent=2))
        return

    sev_rank = {'high': 0, 'low': 1, 'unknown': 2, None: 3}
    print("\n===== UNREGISTERED (hijackable) =====")
    for eco, name, _, sev, where in sorted(missing, key=lambda r: (sev_rank[r[3]], r[0], r[1])):
        tag = f"[{sev}]" if sev else ""
        print(f"  [{eco}] {name}  {tag}")
        for w in where[:4]:
            print(f"        {w}")
    n_high = sum(1 for r in missing if r[3] == 'high')
    n_low = sum(1 for r in missing if r[3] == 'low')
    print(f"\n{len(missing)} unregistered ({n_high} high severity, {n_low} needs-org-compromise), "
          f"{len(unknown)} inconclusive, {present} present")

if __name__ == "__main__":
    main()
