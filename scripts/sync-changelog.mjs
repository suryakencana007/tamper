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
console.log(
  `CHANGELOG.md -> ${target} (${body.split("\n").length} lines; ` +
    `${published} published and ${unpublished} provenance links rewritten)`,
);
