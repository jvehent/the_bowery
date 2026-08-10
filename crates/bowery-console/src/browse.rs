//! Selection + viewport state shared by every browsable pane.
//!
//! Before this existed each pane rendered a stateless `Table`, which meant
//! only the first screenful of any result was reachable and there was no
//! way to point at a row. `Browser` is deliberately pure index arithmetic
//! — no ratatui types — so the clamping and paging rules are unit-testable
//! without constructing a `Frame`.
//!
//! The viewport (`offset`) is kept in sync by [`Browser::visible_range`],
//! which the render path calls once it knows how many rows actually fit.

/// Cursor + scroll offset over a list of `len` items.
#[derive(Debug, Default, Clone)]
pub(crate) struct Browser {
    selected: usize,
    offset: usize,
    len: usize,
}

impl Browser {
    /// Tell the browser how many items exist, keeping the cursor in range.
    ///
    /// Called on every render because pane data changes underneath us (the
    /// alerts poller prepends rows, a query returns a new result set). A
    /// shrinking list must not leave the cursor pointing past the end.
    pub(crate) fn set_len(&mut self, len: usize) {
        self.len = len;
        if len == 0 {
            self.selected = 0;
            self.offset = 0;
        } else if self.selected >= len {
            self.selected = len - 1;
        }
        if self.offset > self.selected {
            self.offset = self.selected;
        }
    }

    /// Index of the selected item, or `None` when the list is empty.
    pub(crate) fn selected(&self) -> Option<usize> {
        (self.len > 0).then_some(self.selected)
    }

    /// Move down one. Stops at the last item rather than wrapping —
    /// wrapping makes it easy to lose your place in a long alert list.
    pub(crate) fn next(&mut self) {
        if self.len > 0 && self.selected + 1 < self.len {
            self.selected += 1;
        }
    }

    pub(crate) fn prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub(crate) fn page_down(&mut self, page: usize) {
        if self.len == 0 {
            return;
        }
        self.selected = (self.selected + page.max(1)).min(self.len - 1);
    }

    pub(crate) fn page_up(&mut self, page: usize) {
        self.selected = self.selected.saturating_sub(page.max(1));
    }

    pub(crate) fn home(&mut self) {
        self.selected = 0;
        self.offset = 0;
    }

    pub(crate) fn end(&mut self) {
        if self.len > 0 {
            self.selected = self.len - 1;
        }
    }

    /// Scroll the viewport so the cursor is visible in a window of
    /// `height` rows, then report the visible slice. Returns an empty
    /// range for an empty list or a zero-height area.
    pub(crate) fn visible_range(&mut self, height: usize) -> std::ops::Range<usize> {
        if self.len == 0 || height == 0 {
            self.offset = 0;
            return 0..0;
        }
        if self.selected < self.offset {
            self.offset = self.selected;
        } else if self.selected >= self.offset + height {
            self.offset = self.selected + 1 - height;
        }
        // A shrinking list can strand the offset past the end.
        let max_offset = self.len.saturating_sub(height);
        if self.offset > max_offset {
            self.offset = max_offset;
        }
        let end = (self.offset + height).min(self.len);
        self.offset..end
    }

    /// Cursor position relative to the visible window — what a ratatui
    /// `TableState` wants when we hand it only the visible slice.
    pub(crate) fn selected_in_view(&self) -> Option<usize> {
        self.selected().map(|s| s.saturating_sub(self.offset))
    }
}

/// Line-oriented scrolling for prose panes (Help, and any future
/// long-text view).
///
/// Split from [`Browser`] because there's no cursor here — just an
/// offset. It clamps to the content length, which the previous ad-hoc
/// implementation in the Help pane did not: you could scroll arbitrarily
/// far past the end into blank space with no way to tell you'd done it.
#[derive(Debug, Default, Clone)]
pub(crate) struct Scroll {
    offset: u16,
    max: u16,
}

impl Scroll {
    /// Set the maximum offset from the content and viewport heights.
    pub(crate) fn set_bounds(&mut self, total_lines: usize, viewport_height: usize) {
        self.max = u16::try_from(total_lines.saturating_sub(viewport_height)).unwrap_or(u16::MAX);
        if self.offset > self.max {
            self.offset = self.max;
        }
    }

    pub(crate) fn offset(&self) -> u16 {
        self.offset
    }

    pub(crate) fn down(&mut self, by: u16) {
        self.offset = self.offset.saturating_add(by).min(self.max);
    }

    pub(crate) fn up(&mut self, by: u16) {
        self.offset = self.offset.saturating_sub(by);
    }

    pub(crate) fn home(&mut self) {
        self.offset = 0;
    }

    pub(crate) fn end(&mut self) {
        self.offset = self.max;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn browser(len: usize) -> Browser {
        let mut b = Browser::default();
        b.set_len(len);
        b
    }

    #[test]
    fn empty_list_has_no_selection() {
        let mut b = browser(0);
        assert_eq!(b.selected(), None);
        // Navigation on an empty list must not panic or invent a cursor.
        b.next();
        b.prev();
        b.page_down(10);
        b.end();
        assert_eq!(b.selected(), None);
        assert_eq!(b.visible_range(10), 0..0);
    }

    #[test]
    fn navigation_stops_at_both_ends() {
        let mut b = browser(3);
        assert_eq!(b.selected(), Some(0));
        b.prev();
        assert_eq!(b.selected(), Some(0), "must not wrap past the top");
        b.next();
        b.next();
        b.next();
        b.next();
        assert_eq!(b.selected(), Some(2), "must not wrap past the bottom");
        b.home();
        assert_eq!(b.selected(), Some(0));
        b.end();
        assert_eq!(b.selected(), Some(2));
    }

    #[test]
    fn paging_clamps() {
        let mut b = browser(100);
        b.page_down(10);
        assert_eq!(b.selected(), Some(10));
        b.page_down(1000);
        assert_eq!(b.selected(), Some(99));
        b.page_up(1000);
        assert_eq!(b.selected(), Some(0));
    }

    #[test]
    fn viewport_follows_the_cursor() {
        let mut b = browser(100);
        assert_eq!(b.visible_range(10), 0..10);

        b.end(); // selected = 99
        let r = b.visible_range(10);
        assert_eq!(r, 90..100, "scrolls down to reveal the last row");
        assert_eq!(b.selected_in_view(), Some(9));

        b.home();
        assert_eq!(b.visible_range(10), 0..10);
        assert_eq!(b.selected_in_view(), Some(0));
    }

    #[test]
    fn shrinking_list_keeps_cursor_and_offset_in_range() {
        // The alerts pane's window slides and query results get replaced,
        // so the underlying list can shrink under a parked cursor.
        let mut b = browser(100);
        b.end();
        let _ = b.visible_range(10); // offset now 90
        b.set_len(5);
        assert_eq!(b.selected(), Some(4), "cursor clamped to the new end");
        assert_eq!(b.visible_range(10), 0..5, "offset pulled back into range");
    }

    #[test]
    fn scroll_clamps_to_content() {
        // The old Help pane scrolled forever into blank space.
        let mut s = Scroll::default();
        s.set_bounds(100, 10); // max offset 90
        s.down(1000);
        assert_eq!(s.offset(), 90);
        s.up(1000);
        assert_eq!(s.offset(), 0);
        s.end();
        assert_eq!(s.offset(), 90);

        // Content shorter than the viewport can't scroll at all.
        let mut s2 = Scroll::default();
        s2.set_bounds(3, 10);
        s2.down(5);
        assert_eq!(s2.offset(), 0);
    }
}
