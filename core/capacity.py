#!/usr/bin/env python3
"""A3 Worker, Durable Object, and Actions capacity model (HLD §9.2).

Every workload figure is an explicit input. External release measurements are
still required by A2, A3, and A6; reproducing the design arithmetic does not
close those gates.
"""

from dataclasses import asdict, dataclass

FREE_WORKER_REQUESTS_DAY = 100_000
PAID_WORKER_REQUESTS_DAY = 10_000_000 / 30
FREE_DO_REQUESTS_DAY = 100_000
FREE_DO_DURATION_GB_S_DAY = 13_000
FREE_DO_ROWS_READ_DAY = 5_000_000
FREE_DO_ROWS_WRITTEN_DAY = 100_000
FREE_DO_STORAGE_BYTES = 5_000_000_000
FREE_ACTIONS_MIN_MONTH = 2_000
CPU_MS_PER_REQUEST_LOWER_BOUND = 1.26
SQLITE_OBJECT_OVERHEAD_BYTES = 12_000
DO_MEMORY_GB = 128 / 1024


@dataclass(frozen=True)
class Assumptions:
    """Inputs per project per day unless the field says otherwise."""

    projects: int = 10
    prs_per_project_day: float = 5
    pull_request_deliveries_per_pr: float = 8
    merge_group_deliveries_per_pr: float = 1
    check_run_deliveries_per_pr: float = 20
    signings_per_project_day: float = 2
    requests_per_signing: float = 8
    maintenance_requests_per_project_day: float = 2
    dashboard_views_project_day: float = 5
    requests_per_dashboard_view: float = 3
    badge_requests_project_day: float = 0
    routed_repositories_per_project: int = 10
    gate_calls_per_merge_group_delivery: float = 3
    publication_row_writes_per_merge_group_delivery: float = 2
    routing_gate_row_writes_per_project_day: float = 0
    gate_duration_seconds: float = 1
    reconcile_schedule_per_day: int = 1
    actions_minutes_per_run: float = 1


def changed(a: Assumptions, **values) -> Assumptions:
    return Assumptions(**{**asdict(a), **values})


def model(a: Assumptions) -> dict[str, float]:
    pull_request_deliveries = (
        a.projects * a.prs_per_project_day
        * a.pull_request_deliveries_per_pr
    )
    merge_group_deliveries = (
        a.projects * a.prs_per_project_day
        * a.merge_group_deliveries_per_pr
    )
    check_run_deliveries = (
        a.projects * a.prs_per_project_day
        * a.check_run_deliveries_per_pr
    )
    signings = (
        a.projects * a.signings_per_project_day * a.requests_per_signing
    )
    maintenance = a.projects * a.maintenance_requests_per_project_day
    dashboard = (
        a.projects * a.dashboard_views_project_day
        * a.requests_per_dashboard_view
    )
    badges = a.projects * a.badge_requests_project_day
    worker_requests = (
        pull_request_deliveries + merge_group_deliveries
        + check_run_deliveries + signings
        + maintenance + dashboard + badges
    )

    # Every sampled pull-request delivery compares the gate. Each merge-group
    # delivery adds the initial comparison, publication reservation, and exact
    # completed-check confirmation. Ordinary and other-App check-run deliveries
    # are rejected by namespace/App identity before a gate RPC.
    gate_requests = (
        pull_request_deliveries
        + merge_group_deliveries * a.gate_calls_per_merge_group_delivery
    )
    gate_duration_gb_s = (
        gate_requests * a.gate_duration_seconds * DO_MEMORY_GB
    )
    object_storage_bytes = (
        a.projects * a.routed_repositories_per_project
        * SQLITE_OBJECT_OVERHEAD_BYTES
    )
    gate_row_writes = (
        merge_group_deliveries
        * a.publication_row_writes_per_merge_group_delivery
        + a.projects * a.routing_gate_row_writes_per_project_day
    )

    # The historical CPU fixture predates the event-wide check-run filter and
    # every revision-13 crypto/team/publication path. Keep reproducing the HLD's
    # old-shape lower-bound column, but do not charge unmeasured check-run work
    # as though the fixture had exercised it.
    historical_cpu_shape_requests = worker_requests - check_run_deliveries

    # Successful synchronous mutations do not dispatch Actions. The normal
    # envelope is the protected control repository's daily schedule only.
    actions_minutes_month = (
        a.reconcile_schedule_per_day * 30 * a.actions_minutes_per_run
    )

    return {
        "pull_request_deliveries": pull_request_deliveries,
        "merge_group_deliveries": merge_group_deliveries,
        "check_run_deliveries": check_run_deliveries,
        "signing_requests": signings,
        "maintenance_requests": maintenance,
        "dashboard_requests": dashboard,
        "worker_requests_day": worker_requests,
        "worker_free_pct": worker_requests / FREE_WORKER_REQUESTS_DAY * 100,
        "worker_paid_pct": worker_requests / PAID_WORKER_REQUESTS_DAY * 100,
        "cpu_seconds_day_lower_bound": (
            historical_cpu_shape_requests
            * CPU_MS_PER_REQUEST_LOWER_BOUND / 1000
        ),
        "gate_requests_day": gate_requests,
        "gate_rows_read_day": gate_requests,
        "gate_rows_written_day": gate_row_writes,
        "gate_free_request_pct": gate_requests / FREE_DO_REQUESTS_DAY * 100,
        "gate_free_row_read_pct": gate_requests / FREE_DO_ROWS_READ_DAY * 100,
        "gate_free_row_write_pct": (
            gate_row_writes / FREE_DO_ROWS_WRITTEN_DAY * 100
        ),
        "gate_duration_gb_s_day": gate_duration_gb_s,
        "gate_free_duration_pct": (
            gate_duration_gb_s / FREE_DO_DURATION_GB_S_DAY * 100
        ),
        "gate_storage_bytes": object_storage_bytes,
        "gate_free_storage_pct": (
            object_storage_bytes / FREE_DO_STORAGE_BYTES * 100
        ),
        "actions_minutes_month": actions_minutes_month,
        "actions_free_pct": (
            actions_minutes_month / FREE_ACTIONS_MIN_MONTH * 100
        ),
    }


def saturation(a: Assumptions, cap: float = FREE_WORKER_REQUESTS_DAY) -> int:
    per_project = model(changed(a, projects=1))["worker_requests_day"]
    return int(cap // per_project) if per_project else 0


def main() -> None:
    base = Assumptions()
    print("\nA3 — capacity envelope\n")
    print("Workers (normal merge-group and event-wide check-run case):")
    print(f"{'projects':>9} {'requests/day':>13} {'% free':>8} {'% paid':>8} "
          f"{'CPU lower s':>12}")
    for projects in (10, 50, 100, 250):
        result = model(changed(base, projects=projects))
        print(f"{projects:>9} {result['worker_requests_day']:>13,.0f} "
              f"{result['worker_free_pct']:>7.1f}% "
              f"{result['worker_paid_pct']:>7.1f}% "
              f"{result['cpu_seconds_day_lower_bound']:>12.1f}")

    print(f"\nWorker Free saturation: approximately {saturation(base):,} projects")
    print("\nDurable Objects (routing gates):")
    print(f"{'projects':>9} {'requests/day':>13} {'% free':>8} "
          f"{'GB-s/day':>10} {'% duration':>11} {'row writes':>11} "
          f"{'storage MB':>11}")
    for projects in (10, 50, 100, 250):
        result = model(changed(base, projects=projects))
        print(f"{projects:>9} {result['gate_requests_day']:>13,.0f} "
              f"{result['gate_free_request_pct']:>7.2f}% "
              f"{result['gate_duration_gb_s_day']:>10,.2f} "
              f"{result['gate_free_duration_pct']:>10.2f}% "
              f"{result['gate_rows_written_day']:>11,.0f} "
              f"{result['gate_storage_bytes'] / 1_000_000:>11.1f}")

    one = model(changed(base, projects=1))
    print("\nGitHub Actions, per project control repository:")
    print(f"  daily schedule at 1 min/run: "
          f"{one['actions_minutes_month']:.0f} min/month "
          f"({one['actions_free_pct']:.1f}% of Free)")
    print("\nA2/A3/A6 external release measurements remain open.")


if __name__ == "__main__":
    main()
