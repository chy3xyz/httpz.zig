# Context

## Glossary

### Action

The verb portion of a Google AIP-136 custom method URL — the segment that follows the final `:` in the path (`POST /users/123:archive` → action is `archive`).

An Action is *not* a path segment or a path parameter; it is a third routing axis alongside HTTP method and path. The Router matches Actions exactly: a Route declaring action `archive` does not match a URL with no action, and vice versa.

AIP-136 requires custom methods to be invoked via POST. Declaring an Action on a Route with any HTTP method other than POST is a comptime error.

Action names match `[A-Za-z][A-Za-z0-9]*` (AIP `camelCase`). A trailing `:tail` whose `tail` does not satisfy this rule is **not** an Action — the `:tail` stays as literal content of the last segment, and `Request.action` remains `null`.

Surfaced on `Request.action: ?[]const u8`. The field is set whenever the URL contains a trailing `:verb` that satisfies the name rule, regardless of whether routing succeeds — fall-through handlers (e.g. 404) can read it.

### Action Separator

The `:` character at the end of a path that introduces an Action. Recognized only when it is not the first character of its segment — that distinguishes it from the `:` that introduces a path parameter (`:id`).

A segment may contain at most one Action Separator, and only the last segment of a path may contain one.

### Route Pattern

The comptime string used to declare a Route's path (e.g. `"/users/:id:archive"`). Three segment forms:

- **Literal** — exact-match path segment (`users`)
- **Param** — single-segment capture, segment begins with `:` (`:id`)
- **Catch-all** — captures the remainder of the path, segment begins with `*`, must be last (`*rest`)

Any segment that is not a catch-all may carry a trailing Action suffix (`:verb`). Catch-all segments cannot.
