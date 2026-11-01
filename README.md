# depconf

Finds dependency-confusion exposure across a set of GitHub repositories:
package names your build manifests reference that **don't exist in the
public registry** — meaning anyone can register that exact name, and any
build that ever falls back to the public registry (directly, or because an
internal mirror misses) will fetch the attacker's code instead of your
internal package.

This only ever reads. It asks the public registry whether a name is taken.
It never registers anything and never touches credentials.

```
===== UNREGISTERED (hijackable) =====
  [npm] @your-internal-scope/build-tools  [high]
        your-org/service-a:packages/api/package.json
  [npm] @acme/legacy-helper  [low]
        your-org/service-b:package.json

2 unregistered (1 high severity, 1 needs-org-compromise), 0 inconclusive, 118 present
```

## Why not just use `confused` or `dependency-combobulator`?

Those are solid, more mature tools, and depconf doesn't try to replace them.
It closes two specific gaps that matter most in practice — false-positive
rate on scoped npm packages, and coverage of monorepos — because those are
what you actually run into on a real org's repo set:

**1. Severity for scoped npm packages.** A missing `@acme/internal-tool`
is not automatically hijackable — only if the `@acme` scope itself is
unclaimed on the public registry. If the org already has *any* public
package there, nobody can publish under that scope without compromising the
org first, so the specific missing package isn't a public squat target.
Treating every missing scoped name as equally severe (which is what a naive
registry check does) overstates risk for the common case of a company that
has *some* public npm presence but keeps other packages private.

depconf checks scope ownership separately, correctly, and the hard way —
npm's documented `scope:` search qualifier turned out not to work (verified
by testing it against `@babel`, which it reported as *unclaimed*, and
against a made-up scope, which it reported as *claimed* — backwards in both
directions). The fix: search for the literal `@scope` text and verify in
code that a returned package name actually starts with `@scope/`, rather
than trusting the qualifier.

**2. Nested manifests.** Most real-world exposure lives in monorepos, where
the actual build manifest is two or three directories deep —
`packages/*/package.json`, `services/*/requirements.txt`. Checking only
root-level files misses almost everything in a modern monorepo. depconf
walks the full repository tree. (On a real-world test against
[vitejs/vite](https://github.com/vitejs/vite): 311 manifests found across
the tree, versus 1 if only the root were checked.)

## Usage

Requires the [`gh` CLI](https://cli.github.com/), authenticated
(`gh auth login`).

```bash
python3 depconf.py repos.txt                # one owner/repo per line
python3 depconf.py repos.txt --jobs 16      # more concurrent registry checks
python3 depconf.py repos.txt --json > out.json
```

Build a repo list from your own org:

```bash
gh repo list your-org --limit 1000 --json nameWithOwner -q '.[].nameWithOwner' > repos.txt
python3 depconf.py repos.txt
```

Try it on the bundled example first:

```bash
python3 depconf.py examples/repos.txt
```

## Supported ecosystems

| Ecosystem | Manifests read |
|---|---|
| npm | `package.json` (all four dependency fields) |
| PyPI | `requirements.txt`, `pyproject.toml` (PEP 621 and Poetry tables) |
| Go | `go.mod` |
| Packagist (PHP) | `composer.json` |

PyPI names are normalized per [PEP 503](https://peps.python.org/pep-0503/)
(`My_Pkg`, `my-pkg`, and `my.pkg` are the same package) so they aren't
double-checked or double-counted.

## Severity

- `high` — the exact name, or its owning scope/org, is unclaimed. Directly
  registerable today.
- `low` — a scoped npm package is missing, but the scope is owned by
  someone. Not a public-registry hijack; would require compromising that
  org.
- unmarked / inconclusive — the registry check was rate-limited or failed
  after retries. Re-run rather than trust a gap here.

## What it is (and isn't)

A name being unregistered is **necessary but not sufficient**. The
dependency might be vendored, resolved only from a private index that never
consults the public one, or simply dead code nothing actually builds. Every
hit needs a human to decide whether a real build would reach for it before
you report or register anything.

## License

MIT — see [LICENSE](LICENSE).
