/** Run: imported by tools/mutations.mjs and tools/local-paths.test.mjs
 *  Prevents: a committed observation recording the absolute path of the checkout
 *            it was produced in, which publishes a developer's home directory.
 *  Reads: nothing. Pure text transform over output captured elsewhere.
 *
 *  Captured tool output names the checkout it ran in -- vitest prints its project
 *  root ("RUN  v4.1.11 <root>") and Playwright prints absolute frames in every
 *  stack trace. audits/mutation-observations.json is COMMITTED, and the catalog's
 *  audit corpus republishes it, so those strings leave this repository. The path
 *  of somebody's working copy is not an observation about Vector Gate: what the
 *  frame is evidence of is `e2e/claims.spec.ts:25`, which is the same line in
 *  every checkout.
 */

/** The three shapes a home-rooted absolute path takes on the platforms this
 *  fleet is built on. Exported so a check can look for them without restating
 *  them, and deliberately NOT anchored to one user or one repository name. */
export const LOCAL_PATH_SHAPES = [
  '/Users/[^/\\s"\'`]+(?:/[^\\s"\'`]*)?',
  '/home/[^/\\s"\'`]+(?:/[^\\s"\'`]*)?',
  '[A-Za-z]:\\\\Users\\\\[^\\\\\\s"\'`]+(?:\\\\[^\\s"\'`]*)?',
];

/* Sources rather than RegExp objects on purpose: a /g regex carries lastIndex,
   so reusing one shared object across calls makes .test() answer about where
   the previous call stopped. One was built per call from the start, because the
   alternative is a check that is right the first time and wrong afterwards. */
const shapeRe = (src) => new RegExp(src, 'g');

/** Rewrites every absolute local path in `text`.
 *
 *  A path INSIDE `root` becomes repo-relative, because that is the part of it
 *  that is true of every checkout. `root` itself becomes "." for the same
 *  reason. Anything else home-rooted -- a cache directory, another checkout,
 *  a path from a machine this run knows nothing about -- becomes the literal
 *  <local-path>, because there is no repo-relative form of it and guessing one
 *  would be worse than saying it was removed.
 */
export function withoutLocalPaths(text, root) {
  if (typeof text !== 'string') return text;
  let out = text;
  if (root) {
    out = out.split(root + '/').join('');
    out = out.split(root + '\\').join('');
    out = out.split(root).join('.');
  }
  for (const src of LOCAL_PATH_SHAPES) out = out.replace(shapeRe(src), '<local-path>');
  return out;
}

/** True when `text` still carries any of the three shapes. */
export function hasLocalPath(text) {
  return typeof text === 'string' && LOCAL_PATH_SHAPES.some((src) => shapeRe(src).test(text));
}
