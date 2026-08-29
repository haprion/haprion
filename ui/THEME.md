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

**Nothing marks a cluster except its name**, and that is deliberate. Four
colour pairs and one set of shapes were tried as a left-edge marker on cluster
cards and activity rows; each was rejected, and the reason turned out to be the
same every time. The cluster name is already adjacent in every place the marker
appeared - as the card heading, and as its own column in Activity - so the
marker never carried information, only weight. Green, amber, blue and red
already mean something here, so a marker in colour also has to be defended
against being read as a status, forever.

If a future view genuinely groups rows from several clusters without showing the
name, add the name. Do not reintroduce a colour.

## Components

Reuse the shared shell, primary navigation, summary cards, status badges,
cluster cards, tables, empty states, and buttons defined in `app.css`. When a
new component is necessary, give it semantic tokens and add it to `app.css` so
the next view inherits the same visual language.
