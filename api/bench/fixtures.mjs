// Realistic payload shapes, sized from what GitHub actually returns.
// The point is to measure parse cost against representative volume, not to
// mock the API.

export function commitListing(n) {
  const commits = [];
  for (let i = 0; i < n; i++) {
    const sha = (i.toString(16).padStart(8, "0")).repeat(5);
    commits.push({
      sha,
      node_id: "C_kwDOABCDEF" + i,
      commit: {
        author: { name: `Contributor ${i}`, email: `c${i}@example.com`,
                  date: "2026-08-18T00:00:00Z" },
        committer: { name: "GitHub", email: "noreply@github.com",
                     date: "2026-08-18T00:00:00Z" },
        message: `Fix the thing in module ${i}\n\nA slightly longer body that ` +
                 `explains why, because real commit messages are not one line.\n\n` +
                 `Co-authored-by: Pair ${i} <${1000 + i}+pair${i}@users.noreply.github.com>`,
        tree: { sha, url: `https://api.github.com/repos/o/r/git/trees/${sha}` },
        url: `https://api.github.com/repos/o/r/git/commits/${sha}`,
        comment_count: 0,
        verification: { verified: false, reason: "unsigned",
                        signature: null, payload: null, verified_at: null },
      },
      url: `https://api.github.com/repos/o/r/commits/${sha}`,
      html_url: `https://github.com/o/r/commit/${sha}`,
      comments_url: `https://api.github.com/repos/o/r/commits/${sha}/comments`,
      author: {
        login: `contributor${i}`, id: 1000 + i, node_id: "MDQ6VXNlcj" + i,
        avatar_url: `https://avatars.githubusercontent.com/u/${1000 + i}?v=4`,
        gravatar_id: "", url: `https://api.github.com/users/contributor${i}`,
        html_url: `https://github.com/contributor${i}`,
        followers_url: `https://api.github.com/users/contributor${i}/followers`,
        following_url: `https://api.github.com/users/contributor${i}/following{/other_user}`,
        gists_url: `https://api.github.com/users/contributor${i}/gists{/gist_id}`,
        starred_url: `https://api.github.com/users/contributor${i}/starred{/owner}{/repo}`,
        subscriptions_url: `https://api.github.com/users/contributor${i}/subscriptions`,
        organizations_url: `https://api.github.com/users/contributor${i}/orgs`,
        repos_url: `https://api.github.com/users/contributor${i}/repos`,
        events_url: `https://api.github.com/users/contributor${i}/events{/privacy}`,
        received_events_url: `https://api.github.com/users/contributor${i}/received_events`,
        type: "User", user_view_type: "public", site_admin: false,
      },
      committer: null,
      parents: [{ sha, url: "", html_url: "" }],
    });
  }
  return JSON.stringify(commits);
}

// The legacy packed coverage shard: 1/256 of a project's contributors. The
// revision-13 design uses 32 encrypted shards; this fixture is a historical
// plaintext lower bound only.
export function coverageShard(users) {
  const doc = {};
  for (let i = 0; i < users; i++) {
    doc[String(1000 + i * 256)] = {
      icla: { decision: "covered", version: "v3",
              digest: "sha256:" + "ab".repeat(32),
              scope: { orgs: ["acme"], repos: ["acme-labs/widget"] },
              since: "2026-08-18T00:00:00Z", reason: "" },
    };
  }
  return JSON.stringify(doc);
}

export function webhookBody() {
  return JSON.stringify({
    action: "synchronize",
    number: 42,
    pull_request: { id: 1, number: 42, state: "open",
      head: { sha: "a".repeat(40), ref: "feature" },
      base: { sha: "b".repeat(40), ref: "main" },
      user: { login: "octocat", id: 583231 } },
    repository: { id: 1, full_name: "acme/widget", private: false,
      owner: { login: "acme", id: 99 } },
    installation: { id: 12345678 },
  });
}
