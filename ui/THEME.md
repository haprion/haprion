# UI theme contract

`base.html` always loads `static/app.css`, which is the single visual theme for
every HAProxy Manager page. New views must reuse it rather than introducing a
page-specific font stack, colour palette, or dark-mode rules.

## Typography

- UI font: locally bundled `Inter Var`, with the NPM-derived fallback stack.
- Base text: 14 px, regular (400), feature settings `cv03`, `cv04`, `cv11`,
  with standard ligatures disabled.
- Use `--text-primary` for names, values, labels, and active navigation.
- Use `--text-secondary` for normal supporting interface text.
- Use `--text-status` for a status qualifier beside a primary label.

The helper classes `.text-primary`, `.text-secondary`, and `.text-status`
exist for markup that does not already have a component selector.

## Colour and state

Use the semantic tokens (`--healthy`, `--warning`, `--critical`, `--info`, and
`--unknown`) with their matching `*-soft` backgrounds. Do not hard-code colour
values in a view. `:root` supplies light mode and `:root[data-theme="dark"]`
supplies dark mode; there is intentionally no system theme.

## Telling clusters apart

**Each cluster carries a low-chroma rule down its left edge**, on cluster cards
and on activity rows, from `--accent-0` through `--accent-3`. The
index comes from `cluster_identity.accent_index`; cluster five repeats cluster
one. The tint is what lets a reader recognise a cluster without reading, which
the name can never do.

Two constraints, both learned the hard way. **Chroma, not hue, is what keeps a
tint from reading as a status** - every status colour here is vivid, so a muted
rule does not compete with one even in the same family; never reach for
`--healthy`, `--warning`, `--critical`, `--info` or `--brand`. And **neighbours
in the cycle must differ in lightness as well as hue**, because the eye reads
lightness first; four earlier colour pairs differed in hue alone and could not
be told apart.

Do not widen the cycle past four without testing it. Hue and lightness together
stretch to about six before a reader starts looking twice, and a marker that has
to be studied is not doing its job.

## Components

Reuse the shared shell, primary navigation, summary cards, status badges,
cluster cards, tables, empty states, and buttons defined in `app.css`. When a
new component is necessary, give it semantic tokens and add it to `app.css` so
the next view inherits the same visual language.

## One line per cell

**Text sits on one line where there is room.** A table cell that stacks a value
over a muted second line, and a summary card that ellipses its own label, are
both the same fault: these pages are read by scanning down a column, and every
cell that becomes two rows halves how many rows fit in one glance.

So: widen the column, shorten the words, or put the values beside each other -
`value · detail`, or a column of their own. A `<span>` under a `<strong>` in a
table cell is almost always wrong here. A summary card carries a number, a
label and a qualifier; if it cannot show all three it is not a smaller card, it
is a broken one, and its grid needs fixing rather than its text truncating.

## Assets are versioned

Every local asset URL carries `?v=<token>`, from `views.asset_token`. Without it
a release ships new markup against the stylesheet a browser already had, which
does not look like a caching problem - it looks like a layout bug in the new
page, and it costs a review round to find. Add the token to any new asset
reference.
