# install-cell: the install matrix's cells and judges

`run.sh` installs a released `noo` on a fresh machine (one cell of
`.github/workflows/install-matrix.yml`). It then runs each judged step through
`lib.sh` `step`. A step's exit code is its verdict, and the judges print one
`<NAME> PASS|FAIL|NOTE: …` line each.

## Reviewing a judge

Before a judge, or a change to one, lands:

1. **Its decision is a pure function over recorded evidence.** It must be unit-tested from fixture evidence, covering PASS, every FAIL shape, NOTE and "not reached". It needs one mutant per check, on the head that lands; a final head has its own verdicts. The I/O gathers facts only, and the facts are written beside the evidence log (for example `logs/<judge>.json`), so a red cell can be read offline.
2. **NOTE means "cannot judge here", never "passed".** When a control fails (the host itself cannot do what the judge expects the product to prevent), the judge says NOTE. The same goes for a probe that did not really try: a missing tool, a usage error or a kill is not a held connection.
3. **Read the whole cell, not only the judge's own lines.** When you report a matrix run, start with its conclusion and every failing job and step (`gh run view <id> --json jobs`, then the `##[error]` lines). Compare them with a run of the same cells without the change. The judge printing PASS while the cell fails is still a failing cell.
4. **What a judge writes must pass the upload gate.** Before anything is uploaded, `cell.py scan` withholds a cell's logs on any secret-shaped text. That includes a line shaped like `<something> key: <word>`, even when the word is harmless. Test every line shape the judge writes against `cell.secret_hits`.
5. **Secrets stay out of the run.** A credential the judge needs is held in memory or in a 0600 file outside the uploaded output. It is passed by file or stdin, never on argv, and the judge checks that no secret value or its sha256 appears in its output.
6. **Runs are sequential.** Before dispatching a matrix run, check that none is in progress on any ref, and say which run you started.
