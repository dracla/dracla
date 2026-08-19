# FAQ

Answers to questions adopters actually ask. Where a design section covers
something in depth, it is linked rather than repeated.

## Setup

### Why does DraCLA want a dedicated organization?

Because the records repository holds contributors' legal names and email
addresses, and in GitHub the *organization* is what controls who can read it.

Most organizations grant every member read access to new repositories by
default. In a two-hundred-person organization that means two hundred people can
read signer data, none of whom asked for it. In an organization created for CLA
records, the same setting governs only the people administering the CLA — which
is the set that should have access anyway.

See [§6.10.4](../design/high-level-design.md).

### Can't I just restrict the repository instead?

No, and this surprises people. A GitHub base permission is a **floor**, not a
default: repository settings can *raise* a member's access and never lower it,
and there are no negative permissions. So if the organization grants members
read, every member keeps read access to that repository no matter what you set
on it.

That is why `dracla install` refuses rather than warning. There is nothing to
warn about — there would be no way to act on the warning.

### Can DraCLA create the organization for me?

No. GitHub has no API for creating an organization: `POST /orgs` does not exist
on github.com, and the admin endpoint is Enterprise Server only. It is a
browser-only operation, so install tells you the two steps and gets out of the
way.

### Who should be a member of it?

The people who would use the evidence if the agreement were ever tested:
whoever the agreement grants rights to, their counsel, and whoever administers
agreement versions.

Not the project's maintainers by default. Being a committer is not a reason to
see who signed and with what email address. Note that membership *is* the
permission — dashboard access is derived from being able to read the records
repository, so there is no second access list to manage.

### Does this apply if I install into my own account?

No. A private repository on a personal account starts with exactly one reader,
and there is no default granting access to anyone else, so the check is skipped
deliberately.

### Why not encrypt the names and email addresses instead?

It was considered and rejected on key custody, not on effort.

Any key would have to be unreachable by the people you are protecting the data
from, yet reachable by the reconciler, which runs unattended. Actions secrets
satisfy both — until you notice that the exports and dashboard index carry the
same names and live in the same repository. Encrypting those too puts the key in
the Worker, and in the hosted deployment that means the operator holds every
adopter's key.

Underneath it: unattended automation cannot hold a secret away from whoever
administers the machine it runs on. Key loss would also make records permanently
unreadable — a failure mode a system of legal evidence should not introduce.

## Using it

### Why does `install` ask for so little?

Because almost nothing about a project needs your own GitHub credentials.
Creating repositories does; naming the legal recipient, choosing scope, writing
a privacy policy link and publishing an agreement do not.

Those are configured in the portal when you connect, where each becomes an event
with an attributable actor rather than a flag someone typed once. See
[§6.10.3](../design/high-level-design.md).

### Do contributors have to install a GitHub App?

No. Contributors only *authorize* the app — the same consent screen as any
"Sign in with GitHub" button. Installation is an administrator action on
repositories, and contributors never do it.

### Why two repositories?

One holds signer data; the other holds a PII-free projection of who is covered.
The component that reads pull requests can reach the second and not the first,
so the code exposed to arbitrary internet traffic structurally cannot read
contributors' names or email addresses.

### Why is the default branch called `events`?

Because records are an append-only event log, and it has to be the *default*
branch: GitHub reads `push:` workflows from the branch being pushed, but runs
scheduled workflows only from the default branch. The reconciler needs both.

## Records and privacy

### Can a contributor have their record deleted?

They can revoke — which stops their acceptance covering future contributions —
but the record itself is retained.

A CLA exists to be provable later, potentially years later and potentially in a
dispute, so the records are append-only by design and retained for the
establishment and defence of legal claims. Both the signing and revocation flows
say this before you act, rather than after. See
[§8.4](../design/high-level-design.md).

If that is unacceptable for your project, it is not something configuration can
change: the append-only record is the product.

### Who is the data controller?

The adopting project — specifically the legal recipient named in your
configuration, which is deliberately not assumed to be the GitHub organization.

If you use the hosted deployment, its operator is a processor, because
contributors type their details into the hosted portal before those reach your
repository. Self-hosting removes that relationship entirely. Not legal advice;
your counsel decides the lawful basis.

### Where does the data actually live?

In private repositories your organization owns, on GitHub. The portal and
enforcement tiers run on Cloudflare and retain nothing. DraCLA adds no storage
of its own, so the destinations to assess are the ones you already use.

## Comparisons

### How is this different from CLA Assistant?

Mostly in where the records live and what happens to them.

CLA Assistant stores signatures in its own database and points at a gist for the
agreement. DraCLA keeps signatures as append-only commits in a repository *you*
own, with no database anywhere, and records the agreement by immutable reference
*and* a snapshot — so the record survives the gist being deleted.

The practical consequence: you can read your records with `git` and a text
editor, and migrating away from a hosted deployment moves nothing.
