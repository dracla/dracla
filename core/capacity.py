#!/usr/bin/env python3
"""A3 capacity envelope (REQ-OPS-3).

Note on who pays: GitHub bills Actions minutes to the account that OWNS the
repository. The canonical records repo lives in the adopting organization
(D4), so reconciler minutes come out of that org's allowance — shared with
every other private repo they own — not out of DraCLA's.

REQ-OPS-3 requires the documented deployment to state its request and compute
assumptions, the applicable provider limits, and the behaviour when those limits
are reached. This computes the first two for any adopter count, so the answer
does not depend on guessing one number.

Assumptions are declared, not buried, and each cites where it came from.
"""

from dataclasses import dataclass

# --- provider limits (verified 18 August 2026) ----------------------------
FREE_REQUESTS_DAY = 100_000          # Cloudflare: per ACCOUNT, not per Worker
PAID_REQUESTS_MONTH = 10_000_000     # $5/mo, per account
PAID_REQUESTS_DAY = PAID_REQUESTS_MONTH / 30
FREE_ACTIONS_MIN_MONTH = 2_000       # GitHub Free, PRIVATE repos only
CPU_MS_PER_CHECK = 1.26              # measured worst case, api/bench/


@dataclass
class Assumptions:
    """Every figure here is an input, not a fact. Change and re-run."""
    projects: int = 10
    prs_per_project_day: float = 5
    deliveries_per_pr: float = 8       # sampled: median 3.5 (uv) to 10.5 (cli/cli)
    signings_per_project_day: float = 2
    requests_per_signing: float = 8    # OAuth start+callback, agreement, POST, status
    dashboard_views_project_day: float = 5
    requests_per_dashboard_view: float = 3   # shell, authz probe, index
    badge_requests_project_day: float = 0    # badges are static assets (§6.7)
    reconcile_schedule_per_day: int = 1      # daily (see design 9.2)
    actions_minutes_per_run: float = 1.0     # GitHub bills whole minutes per job


def model(a: Assumptions) -> dict:
    webhooks = a.projects * a.prs_per_project_day * a.deliveries_per_pr
    portal = a.projects * a.signings_per_project_day * a.requests_per_signing
    dash = (a.projects * a.dashboard_views_project_day
            * a.requests_per_dashboard_view)
    badges = a.projects * a.badge_requests_project_day
    total = webhooks + portal + dash + badges

    # Actions runs happen inside each project's PRIVATE canonical repo, where
    # Free meters minutes. Signing triggers a push; the schedule adds a floor.
    runs_month = (a.signings_per_project_day * 30) + (a.reconcile_schedule_per_day * 30)
    minutes_month = runs_month * a.actions_minutes_per_run

    return {
        "webhooks": webhooks, "portal": portal, "dashboard": dash,
        "total_day": total,
        "free_pct": total / FREE_REQUESTS_DAY * 100,
        "paid_pct": total / PAID_REQUESTS_DAY * 100,
        "cpu_seconds_day": total * CPU_MS_PER_CHECK / 1000,
        "actions_min_month": minutes_month,
        "actions_pct": minutes_month / FREE_ACTIONS_MIN_MONTH * 100,
    }


def saturation(a: Assumptions, cap: float) -> int:
    """How many projects fit under a daily request cap."""
    one = Assumptions(**{**a.__dict__, "projects": 1})
    per = model(one)["total_day"]
    return int(cap // per) if per else 0


def main() -> None:
    base = Assumptions()
    print("\nA3 — capacity envelope\n")
    print("Assumptions (per project per day unless noted):")
    for k, v in base.__dict__.items():
        if k != "projects":
            print(f"  {k:34} {v}")
    print()

    print(f"{'projects':>9} {'req/day':>10} {'% free':>8} {'% paid':>8} "
          f"{'CPU s/day':>10}")
    print("  " + "-" * 47)
    for n in (1, 5, 10, 25, 50, 100, 250):
        m = model(Assumptions(**{**base.__dict__, "projects": n}))
        flag = "" if m["free_pct"] <= 100 else "  <- over Free"
        print(f"{n:>9} {m['total_day']:>10,.0f} {m['free_pct']:>7.1f}% "
              f"{m['paid_pct']:>7.2f}% {m['cpu_seconds_day']:>10.1f}{flag}")

    print()
    print(f"Free tier saturates at  {saturation(base, FREE_REQUESTS_DAY):>4} projects "
          f"({FREE_REQUESTS_DAY:,} req/day, per account)")
    print(f"Paid tier saturates at  {saturation(base, PAID_REQUESTS_DAY):>4} projects "
          f"({PAID_REQUESTS_DAY:,.0f} req/day included)")

    one = model(Assumptions(**{**base.__dict__, "projects": 1}))
    print()
    print("GitHub Actions, per project (private canonical repo, Free = "
          f"{FREE_ACTIONS_MIN_MONTH:,} min/month):")
    print(f"  reconciler runs/month     {one['actions_min_month']:>8,.0f} min"
          f"   {one['actions_pct']:.0f}% of the monthly allowance")
    for per_day, label in ((96, "every 15 min"), (24, "hourly"),
                           (4, "every 6 h"), (1, "daily")):
        m = model(Assumptions(**{**base.__dict__, "projects": 1,
                                 "reconcile_schedule_per_day": per_day}))
        over = "  <- over Free" if m["actions_pct"] > 100 else ""
        print(f"    {label:<14} {m['actions_min_month']:>7,.0f} min"
              f"   {m['actions_pct']:>5.0f}%{over}")


if __name__ == "__main__":
    main()
