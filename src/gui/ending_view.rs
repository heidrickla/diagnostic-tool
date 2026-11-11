//! The small window a recovery process shows after its last window closed, while it waits
//! for the changes still being put back (`timed::DUTIES`): each job's and holder's own
//! stated time, never a fixed one. It closes by itself when nothing is left or every wait
//! is past its time; what is left then goes to the change record and the next start
//! settles it (`recovery::pending`).
use diagnostics::recovery::timed::DUTIES;
use std::time::Duration;
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::HDC;
use windows_sys::Win32::UI::WindowsAndMessaging::DestroyWindow;

use crate::dialog::Dialog;
use crate::toolwin::{self, Ask, ItemState, Page};
use crate::ui::{self, Kind, Tone};

pub const KEY: &str = "ending";

struct EndingView {
    title: Option<HWND>,
    status: Option<HWND>,
    natural: Option<i32>,
}

impl EndingView {
    fn text(left: &[String]) -> String {
        format!(
            "This window closes by itself once Windows has answered. Still being put back: {}.",
            left.join("; ")
        )
    }
}

impl Page for EndingView {
    fn title(&self) -> String {
        "Putting back what changed".into()
    }

    fn size(&self) -> ((i32, i32), (i32, i32)) {
        ((480, 160), (360, 120))
    }

    fn build(&mut self, hwnd: HWND) {
        self.title = Some(ui::text(
            hwnd,
            Kind::Title,
            Tone::Neutral,
            false,
            "Putting back what changed",
        ));
        self.status = Some(ui::text(
            hwnd,
            Kind::Body,
            Tone::Neutral,
            false,
            &Self::text(&DUTIES.left()),
        ));
    }

    fn layout(&mut self, _hwnd: HWND, w: i32, _h: i32, dpi: u32) {
        let (Some(title), Some(status)) = (self.title, self.status) else {
            return;
        };
        let mut f = toolwin::Flow::new(w, dpi);
        f.header(title, status);
        self.natural = Some(f.y);
    }

    fn command(&mut self, _hwnd: HWND, _id: usize, _code: u16) -> Option<Ask> {
        None
    }

    fn tick(&mut self, hwnd: HWND) {
        match DUTIES.waiting(Duration::ZERO) {
            Some(left) => {
                if let Some(status) = self.status {
                    ui::set_text(status, &Self::text(&left));
                }
            }
            // SAFETY: the page's own window.
            None => unsafe {
                DestroyWindow(hwnd);
            },
        }
    }

    fn draw_item(&self, _list: usize, _index: usize, _dc: HDC, _rect: &RECT, _s: ItemState) {}

    fn close_ask(&mut self) -> Option<Ask> {
        Some(Ask {
            dialog: Dialog {
                window_title: "Putting back what changed".into(),
                heading: "Stop waiting?".into(),
                intro: "What is not yet put back is entered in the change record. When the recovery window next starts, it takes off a footer and puts back a read limit that are still this window's, and says the rest.".into(),
                sections: Vec::new(),
                accept: "Stop waiting".into(),
                decline: Some("Keep waiting".into()),
                copy: None,
            },
            then: 0,
        })
    }

    fn natural_height(&self) -> Option<i32> {
        self.natural
    }
}

/// Shows the window and runs until it closes, while anything is still being put back.
/// What is left then is returned, and nothing new starts.
pub fn wait_for_duties(run: impl FnOnce(HWND)) -> Vec<String> {
    DUTIES.ending();
    if DUTIES.waiting(Duration::ZERO).is_some() {
        toolwin::open(std::ptr::null_mut(), KEY, || {
            Box::new(EndingView {
                title: None,
                status: None,
                natural: None,
            })
        });
        toolwin::end_process_with(KEY);
        if let Some(window) = toolwin::window_of(KEY) {
            run(window);
        }
    }
    DUTIES.close()
}
