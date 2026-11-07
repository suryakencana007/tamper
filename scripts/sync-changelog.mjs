// The changelog has ONE source of truth: the repository's CHANGELOG.md. The site page is
// generated from it at build time rather than copied by hand, because a second copy is a
// second thing to forget — and this project has already paid for that once, in a roadmap
// paragraph that still said a closed item needed a product decision.
//
// The generator also rewrites the ONE thing that genuinely differs between the two places the
// file is read: a link written for the repository root ("docs/migrations/…") is a directory
// too deep once the file sits at docs/changelog.md. Two rewrites, both mechanical:
//
//   ./docs/<published>/…  ->  ./<published>/…            (adrs, migrations, design)
//   ./docs/phases|tasks/… ->  an absolute GitHub URL      (intentionally NOT published: the
//                                                        working record, linked as provenance)
import { readFileSync, writeFileSync } from "node:fs";

const REPO = "https://github.com/suryakencana007/tamper/blob/main";
const VERSION_FILE = "docs/.vitepress/version.json";
const source = "CHANGELOG.md";
const target = "docs/changelog.md";

let body = readFileSync(source, "utf8");

let unpublished = 0;
body = body.replace(/\]\(\.\/docs\/(phases|tasks)\/([^)]+)\)/g, (_m, dir, rest) => {
  unpublished++;
  return `](${REPO}/docs/${dir}/${rest})`;
});

let published = 0;
body = body.replace(/\]\(\.\/docs\//g, () => {
  published++;
  return "](./";
});

// The H1 is the site's, and the frontmatter is what the sidebar needs.
const page =
  "---\ntitle: Changelog\ndescription: Every tamper release, generated from the repository's CHANGELOG.md\n---\n\n" +
  body.replace(/^# Changelog\n+/, "");

writeFileSync(target, page);

// The version the site shows comes from the SAME file, for the same reason the changelog page
// does: a hand-kept version string is a second truth. Newest RELEASED heading — `[Unreleased]`
// is not a version, and a site that advertised it would tell visitors to install something
// that does not exist.
const version = body.match(/^## \[(\d+\.\d+\.\d+)\]/m);
if (!version) {
  console.error("no released version heading (## [x.y.z]) found in CHANGELOG.md");
  process.exit(1);
}

// A regex that finds "a version" is not the same as one that finds "the version". Measured, not
// assumed: renaming the newest heading from `## [0.12.0]` to `## 0.12.0` left the match above
// perfectly happy — it fell through to 0.11.0 and published a site that advertised a version
// nobody had released, with exit code 0. So the number is cross-checked against the one other
// place a version is written, the README's `go get` pin, and a disagreement is fatal.
//
// The rule this enforces: the site advertises the newest released version, and the README tells
// people to install it. If those two ever differ, one of them is wrong and neither is safe to
// publish — which is the whole point of generating the first from the changelog.
const pin = readFileSync("README.md", "utf8").match(/tamper@v(\d+\.\d+\.\d+)/);
if (!pin) {
  console.error("README.md has no `tamper@vX.Y.Z` pin to check the site version against");
  process.exit(1);
}
if (pin[1] !== version[1]) {
  console.error(
    `version disagreement: CHANGELOG.md's newest release is v${version[1]} but README.md pins ` +
      `v${pin[1]}. One of them is wrong — refusing to publish either.`,
  );
  process.exit(1);
}
writeFileSync(VERSION_FILE, JSON.stringify({ version: version[1] }, null, 2) + "\n");

console.log(
  `CHANGELOG.md -> ${target} (${body.split("\n").length} lines; ` +
    `${published} published and ${unpublished} provenance links rewritten; ` +
    `site version v${version[1]})`,
);
