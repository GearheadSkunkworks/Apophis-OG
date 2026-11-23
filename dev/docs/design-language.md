# Design language: layout stability

The screen must not jump when the user acts. The thing they touched is the anchor; it stays where it is, and change happens away from it. These rules apply to every view and every new control.

Why: a click that moves the page under the pointer breaks the link between action and result. Browsers already try to hold the view steady ([scroll anchoring](https://developer.mozilla.org/en-US/docs/Web/CSS/overflow-anchor/Guide_to_scroll_anchoring)), and [layout-shift guidance](https://web.dev/articles/cls) treats a shift after a click as acceptable only when it is close to the click and clearly caused by it. Neither helps when an unrelated region above or beside the click changes height, so the layout has to be built not to do that.

## The rules

1. **The anchor stays put.** The control the user acts on never moves on screen. New content grows away from it, normally downward.
2. **Reserve space for what can change.** A region whose content varies is sized for its largest state, so it keeps one height. The timeline always has all of its lanes; empty lanes are simply empty.
3. **Long or variable lists scroll inside a fixed frame.** A list that gets longer or shorter with a filter or selection lives in a box of fixed size (the scenario list is one) and scrolls there. It never resizes the page.
4. **Update in place, or put the anchor back.** Prefer patching the DOM. When a region is rebuilt, record where the acted-on item was on screen before and scroll it back to that place after (`keepAnchored` in `scenario-cards.js`). Keep keyboard focus on the same item.
5. **Motion says where something came from.** An expansion starts at its anchor and finishes within 200 ms. Under reduced motion it just appears.
6. **Test it.** After an action, the anchor's top is within 1 px of where it was. Check this when a view changes, and run the measurement below.

## Where each rule is applied now

- Rule 2: the timeline lays out every scenario so its height and each block's place do not depend on the selection. Every lane uses the same block thickness (8 to 11 px, set by window height), so a crowded lane is taller, never thinner.
- Rule 3: the scenario list under the picker is a fixed-height scroll area.
- Rule 4: the category rail re-renders through `keepAnchored`.

## Measuring

In the browser console on the Compose view, note the anchor's top before and after an action:

```js
const top = () => document.querySelector('.chooser').getBoundingClientRect().top;
const before = top(); /* click a starting point or a category */ const moved = top() - before;   // expect 0
```

The page height should also be the same before and after, apart from content that was meant to grow.
