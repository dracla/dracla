import unittest

from core.capacity import Assumptions, changed, model, saturation


class CapacityModelTests(unittest.TestCase):
    def test_normal_case_reproduces_hld_tables(self):
        result = model(changed(Assumptions(), projects=250))

        self.assertEqual(result["check_run_deliveries"], 25_000)
        self.assertEqual(result["worker_requests_day"], 44_500)
        self.assertAlmostEqual(result["worker_free_pct"], 44.5)
        self.assertAlmostEqual(result["worker_paid_pct"], 13.35)
        self.assertAlmostEqual(result["cpu_seconds_day_lower_bound"], 24.57)

        self.assertEqual(result["gate_requests_day"], 13_750)
        self.assertEqual(result["gate_rows_read_day"], 13_750)
        self.assertEqual(result["gate_rows_written_day"], 2_500)
        self.assertAlmostEqual(result["gate_free_row_write_pct"], 2.5)
        self.assertAlmostEqual(result["gate_duration_gb_s_day"], 1_718.75)
        self.assertAlmostEqual(result["gate_free_duration_pct"], 13.2211538)
        self.assertEqual(result["gate_storage_bytes"], 30_000_000)

    def test_design_sensitivities_are_parameterized(self):
        base = Assumptions()
        full_dashboard = model(changed(
            base, projects=1, requests_per_dashboard_view=34
        ))
        rebuilt_merge_groups = model(changed(
            base, projects=1, merge_group_deliveries_per_pr=10,
            check_run_deliveries_per_pr=100,
        ))

        self.assertEqual(full_dashboard["worker_requests_day"], 333)
        self.assertEqual(rebuilt_merge_groups["worker_requests_day"], 623)
        self.assertEqual(rebuilt_merge_groups["gate_requests_day"], 190)
        self.assertEqual(rebuilt_merge_groups["gate_rows_written_day"], 100)

    def test_event_wide_check_runs_are_filtered_before_the_gate(self):
        base = model(changed(Assumptions(), projects=1))
        noisy = model(changed(
            Assumptions(), projects=1, check_run_deliveries_per_pr=100,
        ))

        self.assertEqual(noisy["worker_requests_day"]
                         - base["worker_requests_day"], 400)
        self.assertEqual(noisy["gate_requests_day"], base["gate_requests_day"])
        self.assertEqual(noisy["gate_rows_written_day"],
                         base["gate_rows_written_day"])

    def test_event_heavy_250_project_sensitivity_matches_hld(self):
        result = model(changed(
            Assumptions(), projects=250,
            merge_group_deliveries_per_pr=10,
            check_run_deliveries_per_pr=100,
        ))

        self.assertEqual(result["worker_requests_day"], 155_750)
        self.assertAlmostEqual(result["worker_free_pct"], 155.75)
        self.assertAlmostEqual(result["worker_paid_pct"], 46.725)
        self.assertEqual(result["gate_requests_day"], 47_500)
        self.assertEqual(result["gate_rows_written_day"], 25_000)
        self.assertAlmostEqual(result["gate_duration_gb_s_day"], 5_937.5)

    def test_actions_counts_only_scheduled_control_run(self):
        one_minute = model(changed(Assumptions(), projects=1))
        two_minutes = model(changed(
            Assumptions(), projects=1, actions_minutes_per_run=2
        ))

        self.assertEqual(one_minute["actions_minutes_month"], 30)
        self.assertAlmostEqual(one_minute["actions_free_pct"], 1.5)
        self.assertEqual(two_minutes["actions_minutes_month"], 60)
        self.assertAlmostEqual(two_minutes["actions_free_pct"], 3)

    def test_worker_saturation_matches_documented_approximation(self):
        base = Assumptions()
        self.assertEqual(saturation(base), 561)
        self.assertEqual(saturation(changed(
            base, merge_group_deliveries_per_pr=10,
            check_run_deliveries_per_pr=100,
        )), 160)
        self.assertEqual(saturation(changed(
            base, requests_per_dashboard_view=34,
        )), 300)


if __name__ == "__main__":
    unittest.main()
