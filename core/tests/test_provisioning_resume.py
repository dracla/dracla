"""Fresh-evidence planning, with a fixture owning-verifier port only."""
from dataclasses import replace
import unittest

from dracla.administration import (AccountRef, AccountObservation, Discovery, Permissions,
                                   RepositoryMetadata, RepositoryObservation)
from dracla.provisioning import (FreshObservations, InstallInput, PlannedRelease, PlannedRepository,
                                 PlannedStep, VerifiedInstallation, plan_install, plan_resume)

RELEASE = PlannedRelease('0.0.1', 'a' * 40, 'sha256:' + 'b' * 64,
                         'sha256:' + 'c' * 64, 'fixture-only-workflow')
CONFIG = InstallInput('acme', 'demo', dry_run=True)


def discovery(ids=(11, 12, 13), *, owner_id=7, visible=True, complete=True, private=True, admin=True):
    owner = AccountRef('acme', owner_id, 'User')
    observations = tuple(RepositoryObservation('acme', f'demo-cla-{role}',
        'missing' if identity is None else 'observed',
        None if identity is None else RepositoryMetadata(owner, f'demo-cla-{role}', identity,
                                                         private, Permissions(admin=admin)))
        for role, identity in zip(('records', 'coverage', 'control'), ids))
    return Discovery(AccountObservation(owner, visible), observations, complete)


class FixtureVerifier:
    """M6 stands in for completed cryptographic/provenance checks in these fixtures.

    Partial or wrong project/generation/root/K/B/manifest evidence cannot produce
    a positive result. This fixture is never reachable from the production CLI.
    """
    def __init__(self, *, valid=True):
        self.valid = valid

    def verify(self, config, release, observed):
        if not self.valid:
            return None
        return VerifiedInstallation(observed.account.account.id, config.slug, release,
            tuple(PlannedRepository(role, config.owner, f'{config.slug}-cla-{role}', o.metadata.id)
                  for role, o in zip(('records', 'coverage', 'control'), observed.repositories)
                  if o.metadata is not None))


class ResumeTests(unittest.TestCase):
    def fresh(self, observed=None, *, verifier=None, config=CONFIG, release=RELEASE):
        observed = discovery() if observed is None else observed
        verified = None if verifier is None else verifier.verify(config, release, observed)
        return FreshObservations(config, release, observed, verified)

    def test_unchanged_observations_reproduce_plan(self):
        for ids in ((None, None, None), (11, None, None), (11, 12, 13)):
            observed = discovery(ids)
            plan = plan_install(CONFIG, RELEASE, observed)
            self.assertEqual(plan_resume(plan, self.fresh(observed)), plan)
            self.assertEqual(plan_resume(plan, self.fresh(observed)),
                             plan_resume(plan, self.fresh(observed)))

    def test_old_completion_flags_and_reasons_have_no_authority(self):
        observed = discovery()
        real = plan_install(CONFIG, RELEASE, observed)
        stale = replace(real, blockers=(), warnings=(),
                        steps=(PlannedStep('forged completion', 'M6', 'satisfied', 'old claim'),))
        fresh = self.fresh(observed)
        self.assertEqual(plan_resume(stale, fresh), real)
        self.assertFalse(plan_resume(stale, fresh).complete)
        self.assertTrue(all(s.state == 'blocked' for s in plan_resume(stale, fresh).steps))

    def test_fresh_exact_verifier_result_allows_classification_only(self):
        observed = discovery()
        old = plan_install(CONFIG, RELEASE, observed)
        fresh = self.fresh(observed, verifier=FixtureVerifier())
        plan = plan_resume(old, fresh)
        self.assertTrue(plan.complete)
        self.assertTrue(all(s.state == 'blocked' for s in plan.steps[1:]))
        self.assertEqual(plan, plan_resume(plan, fresh))
        self.assertIn('A plan does not mean installed', '\n'.join(plan.warnings))

    def test_missing_partial_or_failed_provenance_stays_blocked(self):
        old = plan_install(CONFIG, RELEASE, discovery())
        for ids in ((11, None, None), (11, 12, None), (11, 12, 13)):
            verifiers = (None, FixtureVerifier(valid=False))
            if ids != (11, 12, 13):
                verifiers += (FixtureVerifier(),)
            for verifier in verifiers:
                with self.subTest(ids=ids, verifier=verifier):
                    fresh = self.fresh(discovery(ids), verifier=verifier)
                    plan = plan_resume(old, fresh)
                    self.assertFalse(plan.complete)
                    if ids != (11, 12, 13) or verifier is None or not verifier.valid:
                        self.assertIn('provenance verifier unavailable', '\n'.join(plan.blockers))

    def test_mismatched_or_incomplete_verifier_binding_blocks(self):
        old = plan_install(CONFIG, RELEASE, discovery())
        fresh = self.fresh(verifier=FixtureVerifier())
        evidence = fresh.verified_installation
        wrong = (replace(evidence, owner_id=99), replace(evidence, owner_id=True),
                 replace(evidence, slug='other'), replace(evidence, release=replace(RELEASE, policy_sha256='d')),
                 replace(evidence, repositories=evidence.repositories[:2]),
                 replace(evidence, repositories=evidence.repositories[::-1]),
                 replace(evidence, repositories=(replace(evidence.repositories[0], id=99),) + evidence.repositories[1:]))
        for result in wrong:
            with self.subTest(result=result):
                plan = plan_resume(old, replace(fresh, verified_installation=result))
                self.assertFalse(plan.complete)
                self.assertIn('does not match', '\n'.join(plan.blockers))

        for index, role in enumerate(('records', 'coverage', 'control')):
            ids = [2, 3, 4]
            ids[index] = 1
            observed = discovery(tuple(ids))
            numeric_old = plan_install(CONFIG, RELEASE, observed)
            numeric_fresh = self.fresh(observed, verifier=FixtureVerifier())
            self.assertTrue(plan_resume(numeric_old, numeric_fresh).complete)
            evidence = numeric_fresh.verified_installation
            for invalid_id in (True, 1.0):
                repositories = tuple(
                    replace(repository, id=invalid_id) if repository.role == role else repository
                    for repository in evidence.repositories
                )
                with self.subTest(role=role, invalid_id=invalid_id):
                    plan = plan_resume(numeric_old, replace(numeric_fresh, verified_installation=replace(
                        evidence, repositories=repositories)))
                    self.assertFalse(plan.complete)
                    self.assertIn('does not match', '\n'.join(plan.blockers))

    def test_known_identity_drift_and_disappearance_conflict(self):
        old = plan_install(CONFIG, RELEASE, discovery())
        for observed in (discovery(owner_id=8), discovery((99, 12, 13)), discovery((None, 12, 13)),
                         replace(discovery(), account=AccountObservation(None))):
            fresh = self.fresh(observed, verifier=None)
            plan = plan_resume(old, fresh)
            self.assertFalse(plan.complete)
            self.assertIn('Resume conflict:', '\n'.join(plan.blockers))
            self.assertTrue(all(s.state == 'blocked' for s in plan.steps))

    def test_returned_conflicts_retain_release_and_known_identity_anchors(self):
        old = plan_install(CONFIG, RELEASE, discovery())
        cases = []
        for field in RELEASE.__dataclass_fields__:
            cases.append((f'release_{field}', self.fresh(
                release=replace(RELEASE, **{field: 'changed'}), verifier=FixtureVerifier(),
                config=replace(CONFIG, force=True))))
        cases.extend((
            ('owner_id_drift', self.fresh(discovery(owner_id=8), verifier=FixtureVerifier(),
                                          config=replace(CONFIG, force=True))),
            ('repository_id_drift', self.fresh(discovery((99, 12, 13)), verifier=FixtureVerifier(),
                                               config=replace(CONFIG, force=True))),
            ('repository_disappearance', self.fresh(discovery((None, 12, 13)),
                                                    config=replace(CONFIG, force=True))),
            ('account_unavailable', self.fresh(replace(discovery(), account=AccountObservation(None)),
                                               config=replace(CONFIG, force=True))),
        ))
        for name, fresh in cases:
            with self.subTest(case=name):
                returned = plan_resume(old, fresh)
                for attempt in range(3):
                    self.assertFalse(returned.complete)
                    self.assertEqual(returned.release, old.release)
                    self.assertEqual(returned.owner_id, old.owner_id)
                    self.assertEqual(
                        tuple(repository.id for repository in returned.repositories),
                        tuple(repository.id for repository in old.repositories),
                    )
                    self.assertIn('Resume conflict:', '\n'.join(returned.blockers))
                    self.assertTrue(all(step.state == 'blocked' for step in returned.steps))
                    returned = plan_resume(returned, fresh)

    def test_partial_positive_verifier_evidence_never_clears_readiness(self):
        old = plan_install(CONFIG, RELEASE, discovery((11, None, None)))
        for ids in ((11, None, None), (11, 12, None)):
            with self.subTest(ids=ids):
                fresh = self.fresh(discovery(ids), verifier=FixtureVerifier(),
                                   config=replace(CONFIG, force=True))
                returned = plan_resume(old, fresh)
                self.assertFalse(returned.complete)
                self.assertIn('provenance verifier unavailable', '\n'.join(returned.blockers))

    def test_every_release_binding_and_intent_change_requires_new_plan(self):
        old = plan_install(CONFIG, RELEASE, discovery())
        releases = [replace(RELEASE, **{field: 'changed'}) for field in RELEASE.__dataclass_fields__]
        for release in releases:
            plan = plan_resume(old, self.fresh(release=release, verifier=FixtureVerifier()))
            self.assertIn('release or policy changed', '\n'.join(plan.blockers))
        for config in (replace(CONFIG, owner='elsewhere'), replace(CONFIG, slug='other')):
            plan = plan_resume(old, self.fresh(config=config))
            self.assertEqual((plan.owner, plan.slug), ('acme', 'demo'))
            self.assertIn('owner or slug changed', '\n'.join(plan.blockers))
        malformed = replace(old, repositories=old.repositories[:-1])
        self.assertIn('repository intent changed', '\n'.join(plan_resume(malformed, self.fresh()).blockers))

    def test_force_and_verifier_cannot_bypass_fresh_read_guards_or_engines(self):
        old = plan_install(CONFIG, RELEASE, discovery())
        for changes in ({'visible': False}, {'complete': False}, {'private': False}, {'admin': False}):
            fresh = self.fresh(discovery(**changes), verifier=FixtureVerifier(), config=replace(CONFIG, force=True))
            self.assertFalse(plan_resume(old, fresh).complete)
        fresh = self.fresh(verifier=FixtureVerifier(), config=replace(CONFIG, dry_run=False, force=True))
        self.assertIn('M3, M5 and M6', '\n'.join(plan_resume(old, fresh).blockers))


if __name__ == '__main__':
    unittest.main()
