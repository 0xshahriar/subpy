# Publishing

How a release is produced, and the one thing currently blocking PyPI.

## GitHub release

Triggered by pushing a semver tag:

```bash
git tag -a v1.1.0 -m "subpy 1.1.0"
git push origin v1.1.0
```

`.github/workflows/release.yml` then builds sdist + wheel, validates the
metadata with `twine check --strict`, publishes to PyPI, and creates the
GitHub release with the distributions attached.

The release step pins `target_commitish` to the commit the tag resolves to
rather than letting the action default to the current branch. That default
once recorded a temporary branch name, and when the branch was deleted every
later call to the release-notes API failed with:

```
Invalid target_commitish parameter
```

A commit SHA cannot go stale, so re-running a release for an old tag stays
valid regardless of branches.

## PyPI: the name is taken

`pip install subpy` currently installs **someone else's package**:

| | |
| --- | --- |
| Name | `subpy` |
| Version | 0.2.0 |
| Summary | "a number of useful functions in python" |
| Author | Thatch Lastname (`slaxolotl17@gmail.com`) |

Trusted Publishing cannot claim a name that is already registered, so the
`publish to PyPI` job fails with `invalid-publisher` no matter how the
workflow is configured. Three options:

1. **Rename the distribution.** Available at the time of writing:
   `subpy-dns`, `subpy-cli`. The import package can stay `subpy`, so only
   `pyproject.toml` (`name =`) and the install command change.
2. **Ask the owner to release the name** via
   [PEP 541](https://peps.python.org/pep-0541/). PyPI only transfers a name
   when the incumbent project is abandoned or is not what users would
   reasonably expect; a small, unrelated utility with a similar name is a
   borderline case.
3. **Ship on GitHub only.** Let people install from the repo:
   `pip install git+https://github.com/0xShahriar/subpy.git`

Until one of these is chosen, set the repository variable
`SUBPY_SKIP_PYPI=1` (Settings → Secrets and variables → Actions → Variables)
so the PyPI job is skipped and the release pipeline goes green. The GitHub
release still builds and attaches both distributions.

**Do not** document `pip install subpy` anywhere until this is resolved —
that command installs the other project.

## One-time PyPI setup, if the name is ever obtained

PyPI → Account → Publishing → *Add a new pending publisher*:

| Field | Value |
| --- | --- |
| PyPI project name | `subpy` (or the new name) |
| Owner | `0xShahriar` |
| Repository name | `subpy` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

Then in GitHub: Settings → Environments → create `pypi` (optionally with
required reviewers for a manual approve gate). No API token is stored
anywhere; the workflow exchanges an OIDC token for a short-lived upload
credential.
