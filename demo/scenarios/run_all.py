"""Run every Part R scenario in DEMO MODE (FAKE AIRFLOW (DEMO), MOCK LLM, simulated clock) and print
what happened to each. Nothing here touches a real Airflow.

    python -m demo.scenarios.run_all            # all scenarios
    python -m demo.scenarios.run_all S01 S06    # some of them
"""

import sys

from evaluation.evaluator import MOCK_CAVEAT, run_scenario
from evaluation.scenarios import SCENARIOS


def main(argv: list[str]) -> int:
    chosen = [s for s in SCENARIOS if not argv or s.sid in argv]
    print(f"DEMO MODE - FAKE AIRFLOW (DEMO) - {MOCK_CAVEAT}\n")
    failed = 0
    for scenario in chosen:
        obs = run_scenario(scenario)
        failed += not obs.passed
        clears = "; ".join(",".join(c) for c in obs.clears) or "nothing cleared"
        print(f"[{'OK ' if obs.passed else 'BAD'}] {scenario.sid:<5} (Part R #{scenario.part_r}) {scenario.title}")
        print(f"       diagnosis={obs.category} confidence={obs.confidence} rerun_safety={obs.rerun_safety} "
              f"class={obs.remediation_class} -> final state {obs.final_state}; mutating clears: {clears}")
        for failure in obs.failures:
            print(f"       ! {failure}")
    print(f"\n{len(chosen) - failed}/{len(chosen)} scenarios behaved as expected.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
