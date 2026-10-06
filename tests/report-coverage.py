#!/usr/bin/env python3
"""Report GCC line/branch coverage of the DirectGate sources; use after tests/run-coverage.sh.

Every smoke test compiles its own copy of the sources it needs, next to xcommon and the directgate and dgcli
binaries the end-to-end tests run, so a line counts as executed when any copy executed it, and a branch as
taken when any copy took it."""
import concurrent.futures
import json
import os
import pathlib
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parent.parent
build = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else root / "build-coverage"
sources = root / "src"
output = build / "coverage-report"
gcov = os.environ.get("GCOV", "gcov")
notes = sorted(build.rglob("*.gcno"))
if not notes:
    sys.exit("No GCC coverage notes found; run tests/run-coverage.sh first.")
if not any(build.rglob("*.gcda")):
    sys.exit("No GCC coverage data found; the tests have not run since the last build.")

def read(note):
    result = subprocess.run([gcov, "--json-format", "--stdout", "--branch-probabilities", str(note)],
                            cwd=note.parent, check=True, capture_output=True, text=True)
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]

lines, branches = {}, {}
with concurrent.futures.ThreadPoolExecutor(os.cpu_count() or 4) as pool:
    for reports in pool.map(read, notes):
        for report in reports:
            for entry in report["files"]:
                source = pathlib.Path(entry["file"])
                if not source.is_absolute():
                    source = pathlib.Path(report["current_working_directory"]) / source
                try:
                    relative = str(source.resolve().relative_to(sources))
                except ValueError:
                    continue
                if not relative.endswith(".c"):
                    continue
                executed = lines.setdefault(relative, {})
                taken = branches.setdefault(relative, {})
                for line in entry["lines"]:
                    number = line["line_number"]
                    executed[number] = executed.get(number, False) or line["count"] > 0
                    outcomes = [branch["count"] > 0 for branch in line.get("branches", [])]
                    if not outcomes:
                        continue
                    # A copy built with other definitions can have more branches on the line; the fuller one is kept.
                    known = taken.get(number)
                    if known is None or len(known) < len(outcomes):
                        taken[number] = outcomes
                    elif len(known) == len(outcomes):
                        taken[number] = [was or now for was, now in zip(known, outcomes)]

rows = {}
for name in lines:
    outcomes = [outcome for kept in branches[name].values() for outcome in kept]
    rows[name] = [sum(lines[name].values()), len(lines[name]), sum(outcomes), len(outcomes)]

def percentage(used, total):
    return f"{used}/{total} ({used / total:.1%})" if total else "n/a"

text = ["# Agent coverage", "",
        "All smoke tests are included, merged over every binary that compiles a source; fuzzing is excluded, "
        "and sources this platform does not build are not listed.",
        "", "| Module | Executed lines | Taken branches |", "| --- | ---: | ---: |"]
for name, (used, total, taken, count) in sorted(rows.items()):
    text.append(f"| `{name}` | {percentage(used, total)} | {percentage(taken, count)} |")
totals = [sum(row[i] for row in rows.values()) for i in range(4)]
text.append(f"| **Total** | {percentage(*totals[:2])} | {percentage(*totals[2:])} |")
summary = "\n".join(text) + "\n"

missed = []
for name in sorted(lines):
    code = (sources / name).read_text(errors="replace").splitlines()
    marks = []
    for number in sorted(lines[name]):
        kept = branches[name].get(number, [])
        if not lines[name][number]:
            marks.append(f"{number:6d}  line      {code[number - 1].strip()}")
        elif not all(kept):
            marks.append(f"{number:6d}  {sum(kept):>3}/{len(kept):<3}   {code[number - 1].strip()}")
    if marks:
        missed += [f"== {name}"] + marks + [""]

output.mkdir(parents=True, exist_ok=True)
(output / "summary.md").write_text(summary)
(output / "uncovered.txt").write_text("Lines never executed, and lines with branches some of which were never taken "
                                      "(taken/total).\n\n" + "\n".join(missed))
print(summary)
