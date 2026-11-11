//! Theme, painting and owner-drawn controls in the ui-gallery zinc language.
//! Every visible text is a child window whose text is its accessible name; this module
//! paints it from that text and a small style word, never from session state.
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, Ordering};

use diagnostics::ui_layout::{grid, scale, Rect};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, SIZE, WPARAM};
use windows_sys::Win32::Graphics::Dwm::DwmSetWindowAttribute;
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::Graphics::GdiPlus::*;
use windows_sys::Win32::System::SystemServices::SS_OWNERDRAW;
use windows_sys::Win32::UI::Accessibility::{HCF_HIGHCONTRASTON, HIGHCONTRASTW};
use windows_sys::Win32::UI::Controls::{
    DRAWITEMSTRUCT, ODS_DISABLED, ODS_FOCUS, ODS_NOFOCUSRECT, ODS_SELECTED, WM_MOUSELEAVE,
};
use windows_sys::Win32::UI::HiDpi::GetDpiForWindow;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    TrackMouseEvent, TME_LEAVE, TRACKMOUSEEVENT,
};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

/// NUL-terminated UTF-16 for Win32, never empty.
pub fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

// ---------------------------------------------------------------- palette

#[derive(Clone, Copy)]
pub struct Palette {
    pub page: u32,
    pub card: u32,
    pub border: u32,
    pub raised: u32,
    pub raised_hover: u32,
    pub text: u32,
    pub muted: u32,
    pub subtle: u32,
    pub primary: u32,
    pub primary_hover: u32,
    pub primary_text: u32,
    pub ok: u32,
    pub warn: u32,
    pub serious: u32,
    pub ring: u32,
    pub high_contrast: bool,
}

/// #RRGGBB to a GDI COLORREF (0x00BBGGRR).
pub const fn rgb(hex: u32) -> u32 {
    ((hex & 0xFF) << 16) | (hex & 0xFF00) | ((hex >> 16) & 0xFF)
}

const DARK: Palette = Palette {
    page: rgb(0x09090B),
    card: rgb(0x18181B),
    border: rgb(0x27272A),
    raised: rgb(0x27272A),
    raised_hover: rgb(0x3F3F46),
    text: rgb(0xFAFAFA),
    muted: rgb(0xA1A1AA),
    subtle: rgb(0x71717A),
    primary: rgb(0xFAFAFA),
    primary_hover: rgb(0xE4E4E7),
    primary_text: rgb(0x18181B),
    ok: rgb(0x34D399),
    warn: rgb(0xFBBF24),
    serious: rgb(0xF87171),
    ring: rgb(0xA1A1AA),
    high_contrast: false,
};

fn high_contrast_on() -> bool {
    let mut info: HIGHCONTRASTW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<HIGHCONTRASTW>() as u32;
    let ok = unsafe {
        SystemParametersInfoW(
            SPI_GETHIGHCONTRAST,
            info.cbSize,
            &mut info as *mut _ as *mut _,
            0,
        )
    };
    ok != 0 && info.dwFlags & HCF_HIGHCONTRASTON != 0
}

/// The dark zinc palette, or the user's system colours while high contrast is on.
pub fn palette() -> Palette {
    if !high_contrast_on() {
        return DARK;
    }
    let sys = |index| unsafe { GetSysColor(index) };
    Palette {
        page: sys(COLOR_WINDOW),
        card: sys(COLOR_WINDOW),
        border: sys(COLOR_WINDOWTEXT),
        raised: sys(COLOR_BTNFACE),
        raised_hover: sys(COLOR_HIGHLIGHT),
        text: sys(COLOR_WINDOWTEXT),
        muted: sys(COLOR_WINDOWTEXT),
        subtle: sys(COLOR_GRAYTEXT),
        primary: sys(COLOR_HIGHLIGHT),
        primary_hover: sys(COLOR_HIGHLIGHT),
        primary_text: sys(COLOR_HIGHLIGHTTEXT),
        ok: sys(COLOR_WINDOWTEXT),
        warn: sys(COLOR_WINDOWTEXT),
        serious: sys(COLOR_WINDOWTEXT),
        ring: sys(COLOR_HIGHLIGHT),
        high_contrast: true,
    }
}

thread_local! {
    static PALETTE: RefCell<Palette> = const { RefCell::new(DARK) };
    static FONTS: RefCell<HashMap<u32, Fonts>> = RefCell::new(HashMap::new());
    static CARDS: RefCell<HashMap<isize, Vec<Rect>>> = RefCell::new(HashMap::new());
}

pub fn current() -> Palette {
    PALETTE.with(|p| *p.borrow())
}

/// Re-reads the palette after a system colour or contrast change.
pub fn refresh_palette() {
    PALETTE.with(|p| *p.borrow_mut() = palette());
}

// ---------------------------------------------------------------- fonts

#[derive(Clone, Copy)]
pub struct Fonts {
    pub title: HFONT,
    pub body: HFONT,
    pub strong: HFONT,
    pub caption: HFONT,
}

fn face_available(face: &str) -> bool {
    let font = make_font(face, 14, 400);
    let dc = unsafe { GetDC(std::ptr::null_mut()) };
    let old = unsafe { SelectObject(dc, font) };
    let mut buffer = [0u16; 64];
    let len = unsafe { GetTextFaceW(dc, buffer.len() as i32, buffer.as_mut_ptr()) };
    unsafe {
        SelectObject(dc, old);
        ReleaseDC(std::ptr::null_mut(), dc);
        DeleteObject(font);
    }
    len > 0 && String::from_utf16_lossy(&buffer[..(len as usize).saturating_sub(1)]) == face
}

fn make_font(face: &str, px: i32, weight: i32) -> HFONT {
    let face = wide(face);
    unsafe {
        CreateFontW(
            -px,
            0,
            0,
            0,
            weight,
            0,
            0,
            0,
            DEFAULT_CHARSET as u32,
            OUT_DEFAULT_PRECIS as u32,
            CLIP_DEFAULT_PRECIS as u32,
            CLEARTYPE_QUALITY as u32,
            (DEFAULT_PITCH | FF_SWISS) as u32,
            face.as_ptr(),
        )
    }
}

/// Segoe UI Variable on Windows 11, Segoe UI elsewhere; one set per DPI.
pub fn fonts(dpi: u32) -> Fonts {
    FONTS.with(|cache| {
        *cache.borrow_mut().entry(dpi).or_insert_with(|| {
            let (text, display) = if face_available("Segoe UI Variable Text") {
                ("Segoe UI Variable Text", "Segoe UI Variable Display")
            } else {
                ("Segoe UI", "Segoe UI")
            };
            Fonts {
                title: make_font(display, scale(dpi, 20), 600),
                body: make_font(text, scale(dpi, 14), 400),
                strong: make_font(text, scale(dpi, 14), 600),
                caption: make_font(text, scale(dpi, 12), 400),
            }
        })
    })
}

pub fn dpi_of(hwnd: HWND) -> u32 {
    #[cfg(debug_assertions)]
    if let Some(dpi) = test_dpi() {
        return dpi;
    }
    match unsafe { GetDpiForWindow(hwnd) } {
        0 => 96,
        dpi => dpi,
    }
}

/// A debug build lays its windows out at DIAGTOOL_TEST_DPI (96 to 288) when it is set, so
/// a display scale can be checked without changing Windows' own setting.
#[cfg(debug_assertions)]
fn test_dpi() -> Option<u32> {
    static DPI: std::sync::OnceLock<Option<u32>> = std::sync::OnceLock::new();
    *DPI.get_or_init(|| {
        std::env::var("DIAGTOOL_TEST_DPI")
            .ok()?
            .parse()
            .ok()
            .filter(|dpi| (96..=288).contains(dpi))
    })
}

/// Width in pixels of one line of text in a font.
pub fn text_width(hwnd: HWND, font: HFONT, text: &str) -> i32 {
    let dc = unsafe { GetDC(hwnd) };
    let old = unsafe { SelectObject(dc, font) };
    // Never an empty Vec: its pointer is dangling, and DrawTextW reads it even for zero length.
    let utf16 = wide(text);
    let mut size = SIZE { cx: 0, cy: 0 };
    unsafe {
        GetTextExtentPoint32W(dc, utf16.as_ptr(), (utf16.len() - 1) as i32, &mut size);
        SelectObject(dc, old);
        ReleaseDC(hwnd, dc);
    }
    size.cx
}

/// Height of word-wrapped text in a given width.
pub fn text_height(hwnd: HWND, font: HFONT, text: &str, width: i32) -> i32 {
    let dc = unsafe { GetDC(hwnd) };
    let old = unsafe { SelectObject(dc, font) };
    // Never an empty Vec: its pointer is dangling, and DrawTextW reads it even for zero length.
    let utf16 = wide(text);
    let mut rect = RECT {
        left: 0,
        top: 0,
        right: width,
        bottom: 0,
    };
    unsafe {
        DrawTextW(
            dc,
            utf16.as_ptr(),
            (utf16.len() - 1) as i32,
            &mut rect,
            DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX,
        );
        SelectObject(dc, old);
        ReleaseDC(hwnd, dc);
    }
    rect.bottom
}

// ---------------------------------------------------------------- GDI+ shapes

static GDIPLUS: AtomicI32 = AtomicI32::new(0);

/// Starts GDI+ once for the process; shapes fall back to square GDI if it fails.
pub fn start_gdiplus() {
    let input = GdiplusStartupInput {
        GdiplusVersion: 1,
        DebugEventCallback: 0,
        SuppressBackgroundThread: 0,
        SuppressExternalCodecs: 0,
    };
    let mut token = 0usize;
    let status = unsafe { GdiplusStartup(&mut token, &input, std::ptr::null_mut()) };
    GDIPLUS.store(i32::from(status == Ok), Ordering::SeqCst);
}

fn argb(color: u32) -> u32 {
    0xFF00_0000 | ((color & 0xFF) << 16) | (color & 0xFF00) | ((color >> 16) & 0xFF)
}

pub(crate) struct Canvas {
    graphics: *mut GpGraphics,
}

impl Canvas {
    pub(crate) fn new(dc: HDC) -> Option<Self> {
        if GDIPLUS.load(Ordering::SeqCst) == 0 {
            return None;
        }
        let mut graphics = std::ptr::null_mut();
        if unsafe { GdipCreateFromHDC(dc, &mut graphics) } != Ok {
            return None;
        }
        unsafe {
            GdipSetSmoothingMode(graphics, SmoothingModeAntiAlias);
            GdipSetPixelOffsetMode(graphics, PixelOffsetModeHalf);
        }
        Some(Self { graphics })
    }

    fn rounded(x: f32, y: f32, w: f32, h: f32, r: f32) -> *mut GpPath {
        let mut path = std::ptr::null_mut();
        let d = (2.0 * r).min(w).min(h);
        unsafe {
            GdipCreatePath(FillModeAlternate, &mut path);
            GdipAddPathArc(path, x, y, d, d, 180.0, 90.0);
            GdipAddPathArc(path, x + w - d, y, d, d, 270.0, 90.0);
            GdipAddPathArc(path, x + w - d, y + h - d, d, d, 0.0, 90.0);
            GdipAddPathArc(path, x, y + h - d, d, d, 90.0, 90.0);
            GdipClosePathFigure(path);
        }
        path
    }

    pub(crate) fn fill_round(&self, rect: (f32, f32, f32, f32), radius: f32, color: u32) {
        let path = Self::rounded(rect.0, rect.1, rect.2, rect.3, radius);
        let mut brush = std::ptr::null_mut();
        unsafe {
            GdipCreateSolidFill(argb(color), &mut brush);
            GdipFillPath(self.graphics, brush as *mut GpBrush, path);
            GdipDeleteBrush(brush as *mut GpBrush);
            GdipDeletePath(path);
        }
    }

    pub(crate) fn stroke_round(
        &self,
        rect: (f32, f32, f32, f32),
        radius: f32,
        color: u32,
        width: f32,
    ) {
        let half = width / 2.0;
        let path = Self::rounded(
            rect.0 + half,
            rect.1 + half,
            rect.2 - width,
            rect.3 - width,
            radius,
        );
        let pen = self.pen(color, width);
        unsafe {
            GdipDrawPath(self.graphics, pen, path);
            GdipDeletePen(pen);
            GdipDeletePath(path);
        }
    }

    fn pen(&self, color: u32, width: f32) -> *mut GpPen {
        let mut pen = std::ptr::null_mut();
        unsafe {
            GdipCreatePen1(argb(color), width, UnitPixel, &mut pen);
            GdipSetPenStartCap(pen, LineCapRound);
            GdipSetPenEndCap(pen, LineCapRound);
            GdipSetPenLineJoin(pen, LineJoinRound);
        }
        pen
    }

    pub(crate) fn circle(&self, cx: f32, cy: f32, r: f32, color: u32) {
        let mut brush = std::ptr::null_mut();
        unsafe {
            GdipCreateSolidFill(argb(color), &mut brush);
            GdipFillEllipse(
                self.graphics,
                brush as *mut GpBrush,
                cx - r,
                cy - r,
                2.0 * r,
                2.0 * r,
            );
            GdipDeleteBrush(brush as *mut GpBrush);
        }
    }

    /// `circle` is centre x, centre y and radius.
    pub(crate) fn arc(
        &self,
        circle: (f32, f32, f32),
        start: f32,
        sweep: f32,
        color: u32,
        width: f32,
    ) {
        let (cx, cy, r) = circle;
        let pen = self.pen(color, width);
        unsafe {
            GdipDrawArc(
                self.graphics,
                pen,
                cx - r,
                cy - r,
                2.0 * r,
                2.0 * r,
                start,
                sweep,
            );
            GdipDeletePen(pen);
        }
    }

    pub(crate) fn polyline(&self, points: &[(f32, f32)], color: u32, width: f32) {
        let pen = self.pen(color, width);
        for pair in points.windows(2) {
            unsafe {
                GdipDrawLine(
                    self.graphics,
                    pen,
                    pair[0].0,
                    pair[0].1,
                    pair[1].0,
                    pair[1].1,
                )
            };
        }
        unsafe { GdipDeletePen(pen) };
    }

    /// A connected line through `points` in one call, with flat ends, for a graph's trace.
    pub(crate) fn trace(&self, points: &[(f32, f32)], color: u32, width: f32) {
        if points.len() < 2 {
            return;
        }
        let points: Vec<PointF> = points.iter().map(|&(x, y)| PointF { X: x, Y: y }).collect();
        let mut pen = std::ptr::null_mut();
        unsafe {
            GdipCreatePen1(argb(color), width, UnitPixel, &mut pen);
            GdipSetPenLineJoin(pen, LineJoinRound);
            GdipDrawLines(self.graphics, pen, points.as_ptr(), points.len() as i32);
            GdipDeletePen(pen);
        }
    }

    /// Fills the polygon through `points`.
    pub(crate) fn fill_polygon(&self, points: &[(f32, f32)], color: u32) {
        if points.len() < 3 {
            return;
        }
        let points: Vec<PointF> = points.iter().map(|&(x, y)| PointF { X: x, Y: y }).collect();
        let mut brush = std::ptr::null_mut();
        unsafe {
            GdipCreateSolidFill(argb(color), &mut brush);
            GdipFillPolygon(
                self.graphics,
                brush as *mut GpBrush,
                points.as_ptr(),
                points.len() as i32,
                FillModeAlternate,
            );
            GdipDeleteBrush(brush as *mut GpBrush);
        }
    }
}

impl Drop for Canvas {
    fn drop(&mut self) {
        unsafe { GdipDeleteGraphics(self.graphics) };
    }
}

pub(crate) fn fill_rect(dc: HDC, rect: &RECT, color: u32) {
    unsafe {
        let brush = CreateSolidBrush(color);
        FillRect(dc, rect, brush);
        DeleteObject(brush);
    }
}

pub(crate) fn draw_text(dc: HDC, text: &str, rect: &RECT, font: HFONT, color: u32, format: u32) {
    // Never an empty Vec: its pointer is dangling, and DrawTextW reads it even for zero length.
    let utf16 = wide(text);
    let mut rect = *rect;
    unsafe {
        let old = SelectObject(dc, font);
        SetBkMode(dc, TRANSPARENT as i32);
        SetTextColor(dc, color);
        DrawTextW(
            dc,
            utf16.as_ptr(),
            (utf16.len() - 1) as i32,
            &mut rect,
            format | DT_NOPREFIX,
        );
        SelectObject(dc, old);
    }
}

// ---------------------------------------------------------------- control styles

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Title = 1,
    Body,
    Muted,
    Caption,
    Heading,
    Bullet,
    Row,
    Badge,
    Progress,
    Primary,
    Secondary,
    Ghost,
    Pair,
    Icon,
    /// A text button with a download arrow, for an available update.
    Update,
    /// A small card with a caption and a value, text "label\nvalue"; Ok, Warn and Serious
    /// tones put a coloured dot beside the label.
    Tile,
}

/// Status of a check row, a bullet or a badge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Tone {
    Neutral = 0,
    Waiting,
    Running,
    Ok,
    Flag,
    Unavailable,
    NotRun,
    Yes,
    No,
    Warn,
    Serious,
}

const HOT: isize = 1 << 16;
const ON_CARD: isize = 1 << 17;
const FIRST: isize = 1 << 18;
/// A result row that opens a tool when clicked.
const LINK: isize = 1 << 19;

fn kind_of(word: isize) -> u8 {
    (word & 0xFF) as u8
}

fn tone_of(word: isize) -> Tone {
    match (word >> 8) & 0xFF {
        1 => Tone::Waiting,
        2 => Tone::Running,
        3 => Tone::Ok,
        4 => Tone::Flag,
        5 => Tone::Unavailable,
        6 => Tone::NotRun,
        7 => Tone::Yes,
        8 => Tone::No,
        9 => Tone::Warn,
        10 => Tone::Serious,
        _ => Tone::Neutral,
    }
}

fn style_word(hwnd: HWND) -> isize {
    unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) }
}

fn set_style_word(hwnd: HWND, word: isize) {
    unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, word) };
}

pub fn set_tone(hwnd: HWND, tone: Tone) {
    let word = style_word(hwnd);
    let next = (word & !0xFF00) | ((tone as isize) << 8);
    if next != word {
        set_style_word(hwnd, next);
        unsafe { InvalidateRect(hwnd, std::ptr::null(), 0) };
    }
}

pub fn set_value(hwnd: HWND, permille: u32) {
    let word = style_word(hwnd);
    let next = (word & 0xF_FFFF) | ((permille.min(1000) as isize) << 20);
    if next != word {
        set_style_word(hwnd, next);
        unsafe { InvalidateRect(hwnd, std::ptr::null(), 0) };
    }
}

pub fn set_text(hwnd: HWND, text: &str) {
    if window_text(hwnd) != text {
        unsafe {
            SetWindowTextW(hwnd, wide(text).as_ptr());
            InvalidateRect(hwnd, std::ptr::null(), 0);
        }
    }
}

pub fn window_text(hwnd: HWND) -> String {
    let len = unsafe { GetWindowTextLengthW(hwnd) };
    let mut buffer = vec![0u16; len as usize + 1];
    let got = unsafe { GetWindowTextW(hwnd, buffer.as_mut_ptr(), buffer.len() as i32) };
    String::from_utf16_lossy(&buffer[..got.max(0) as usize])
}

/// Creates a painted text control. The text is also what screen readers announce.
pub fn text(parent: HWND, kind: Kind, tone: Tone, on_card: bool, value: &str) -> HWND {
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            wide("STATIC").as_ptr(),
            wide(value).as_ptr(),
            WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
            0,
            0,
            0,
            0,
            parent,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    };
    let card = if on_card { ON_CARD } else { 0 };
    set_style_word(hwnd, kind as isize | ((tone as isize) << 8) | card);
    hwnd
}

/// Read-only text the user can select and copy: drag, Ctrl+C or the right-click menu.
pub fn selectable(parent: HWND, value: &str) -> HWND {
    selectable_styled(parent, value, 0)
}

/// `selectable` with a dark vertical scroll bar, for text longer than its box.
pub fn selectable_scrolling(parent: HWND, value: &str) -> HWND {
    let hwnd = selectable_styled(parent, value, WS_VSCROLL | ES_AUTOVSCROLL as u32);
    if !current().high_contrast {
        use windows_sys::Win32::UI::Controls::SetWindowTheme;
        unsafe { SetWindowTheme(hwnd, wide("DarkMode_Explorer").as_ptr(), std::ptr::null()) };
    }
    hwnd
}

fn selectable_styled(parent: HWND, value: &str, extra: u32) -> HWND {
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            wide("EDIT").as_ptr(),
            wide(value).as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | (ES_MULTILINE | ES_READONLY) as u32 | extra,
            0,
            0,
            0,
            0,
            parent,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    };
    // No inner margins, so the text lines up with the painted labels beside it.
    use windows_sys::Win32::UI::Controls::EM_SETMARGINS;
    unsafe {
        SendMessageW(
            hwnd,
            EM_SETMARGINS,
            (EC_LEFTMARGIN | EC_RIGHTMARGIN) as usize,
            0,
        )
    };
    hwnd
}

pub fn set_font(hwnd: HWND, font: HFONT) {
    unsafe { SendMessageW(hwnd, WM_SETFONT, font as usize, 0) };
}

/// Colours for a read-only edit on a card: the answer to WM_CTLCOLORSTATIC.
pub fn selectable_colors(dc: HDC) -> LRESULT {
    let colors = current();
    unsafe {
        SetTextColor(dc, colors.text);
        SetBkColor(dc, colors.card);
        SetDCBrushColor(dc, colors.card);
        GetStockObject(DC_BRUSH) as LRESULT
    }
}

/// Puts text on the clipboard as Unicode; false when Windows refused.
pub fn copy_to_clipboard(owner: HWND, text: &str) -> bool {
    use windows_sys::Win32::Foundation::GlobalFree;
    use windows_sys::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
    };
    use windows_sys::Win32::System::Memory::{
        GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE,
    };
    const CF_UNICODETEXT: u32 = 13;
    let utf16 = wide(text);
    let bytes = utf16.len() * 2;
    unsafe {
        if OpenClipboard(owner) == 0 {
            return false;
        }
        let mut done = false;
        if EmptyClipboard() != 0 {
            let memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
            if !memory.is_null() {
                let target = GlobalLock(memory) as *mut u16;
                if !target.is_null() {
                    std::ptr::copy_nonoverlapping(utf16.as_ptr(), target, utf16.len());
                    GlobalUnlock(memory);
                    // On success the clipboard owns the memory.
                    done = !SetClipboardData(CF_UNICODETEXT, memory as _).is_null();
                }
                if !done {
                    GlobalFree(memory);
                }
            }
        }
        CloseClipboard();
        done
    }
}

/// Paints a control made with `button` or `text` as sitting on a card, not the page.
pub fn mark_on_card(hwnd: HWND) {
    set_style_word(hwnd, style_word(hwnd) | ON_CARD);
}

pub fn mark_first(hwnd: HWND) {
    set_style_word(hwnd, style_word(hwnd) | FIRST);
}

static BUTTON_PROC: std::sync::OnceLock<isize> = std::sync::OnceLock::new();

unsafe extern "system" fn button_proc(hwnd: HWND, msg: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    match msg {
        WM_MOUSEMOVE if style_word(hwnd) & HOT == 0 => {
            set_style_word(hwnd, style_word(hwnd) | HOT);
            let mut track = TRACKMOUSEEVENT {
                cbSize: std::mem::size_of::<TRACKMOUSEEVENT>() as u32,
                dwFlags: TME_LEAVE,
                hwndTrack: hwnd,
                dwHoverTime: 0,
            };
            TrackMouseEvent(&mut track);
            InvalidateRect(hwnd, std::ptr::null(), 0);
        }
        WM_MOUSELEAVE => {
            set_style_word(hwnd, style_word(hwnd) & !HOT);
            InvalidateRect(hwnd, std::ptr::null(), 0);
        }
        WM_SETCURSOR if style_word(hwnd) & LINK != 0 => {
            SetCursor(LoadCursorW(std::ptr::null_mut(), IDC_HAND));
            return 1;
        }
        // Painted fully by the owner; skipping erase avoids a flash of the class brush.
        WM_ERASEBKGND => return 1,
        _ => {}
    }
    let original = *BUTTON_PROC.get().unwrap_or(&0);
    if original == 0 {
        return DefWindowProcW(hwnd, msg, w, l);
    }
    let original: WNDPROC = std::mem::transmute(original);
    CallWindowProcW(original, hwnd, msg, w, l)
}

/// Creates an owner-drawn push button with hover tracking.
pub fn button(parent: HWND, id: usize, kind: Kind, caption: &str) -> HWND {
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            wide("BUTTON").as_ptr(),
            wide(caption).as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW as u32,
            0,
            0,
            0,
            0,
            parent,
            id as HMENU,
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    };
    set_style_word(hwnd, kind as isize);
    let previous =
        unsafe { SetWindowLongPtrW(hwnd, GWLP_WNDPROC, button_proc as *const () as isize) };
    let _ = BUTTON_PROC.set(previous);
    hwnd
}

/// A result row that opens a tool: a button drawn as a row, with a chevron and a hand pointer.
pub fn row_button(parent: HWND, id: usize, value: &str) -> HWND {
    let hwnd = button(parent, id, Kind::Row, value);
    set_style_word(
        hwnd,
        Kind::Row as isize | ((Tone::Waiting as isize) << 8) | ON_CARD | LINK,
    );
    hwnd
}

pub fn set_kind(hwnd: HWND, kind: Kind) {
    let word = style_word(hwnd);
    let next = (word & !0xFF) | kind as isize;
    if next != word {
        set_style_word(hwnd, next);
        unsafe { InvalidateRect(hwnd, std::ptr::null(), 0) };
    }
}

pub fn place(hwnd: HWND, rect: Rect) {
    unsafe {
        SetWindowPos(
            hwnd,
            std::ptr::null_mut(),
            rect.x,
            rect.y,
            rect.w,
            rect.h,
            SWP_NOZORDER | SWP_NOACTIVATE,
        )
    };
}

/// The kind a control was made as, if this module made it.
pub fn kind(hwnd: HWND) -> Option<Kind> {
    const KINDS: [Kind; 16] = [
        Kind::Title,
        Kind::Body,
        Kind::Muted,
        Kind::Caption,
        Kind::Heading,
        Kind::Bullet,
        Kind::Row,
        Kind::Badge,
        Kind::Progress,
        Kind::Primary,
        Kind::Secondary,
        Kind::Ghost,
        Kind::Pair,
        Kind::Icon,
        Kind::Update,
        Kind::Tile,
    ];
    let k = kind_of(style_word(hwnd));
    KINDS.into_iter().find(|kind| *kind as u8 == k)
}

/// Whether the control is set to show, whether or not its window is on screen yet: layout
/// runs before a window is first shown, and a page's height is measured then.
pub fn visible(hwnd: HWND) -> bool {
    unsafe { GetWindowLongPtrW(hwnd, GWL_STYLE) as u32 & WS_VISIBLE != 0 }
}

pub fn show(hwnd: HWND, visible: bool) {
    unsafe { ShowWindow(hwnd, if visible { SW_SHOWNA } else { SW_HIDE }) };
}

pub fn enable(hwnd: HWND, enabled: bool) {
    unsafe {
        windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow(hwnd, i32::from(enabled))
    };
}

/// A visible control's rectangle in its parent's client coordinates, for hit tests on the
/// parent's surface.
pub fn rect_in_parent(hwnd: HWND) -> Option<RECT> {
    if !visible(hwnd) {
        return None;
    }
    let mut rect = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    unsafe {
        if GetWindowRect(hwnd, &mut rect) == 0 {
            return None;
        }
        let parent = GetParent(hwnd);
        MapWindowPoints(
            std::ptr::null_mut(),
            parent,
            &mut rect as *mut RECT as *mut _,
            2,
        );
    }
    Some(rect)
}

/// Measured button width for its caption at the window's DPI.
pub fn button_width(hwnd: HWND, caption: &str) -> i32 {
    let dpi = dpi_of(hwnd);
    let width = text_width(hwnd, fonts(dpi).strong, caption);
    diagnostics::ui_layout::button_width(dpi, width)
}

// ---------------------------------------------------------------- window surface

/// Records the card rectangles a window paints behind its children.
pub fn set_cards(hwnd: HWND, cards: Vec<Rect>) {
    if store_cards(hwnd as isize, cards) {
        unsafe { InvalidateRect(hwnd, std::ptr::null(), 1) };
    }
}

/// Keeps a window's cards, and says whether they changed. A page lays itself out on every
/// timer tick and sets the same cards each time; repainting the whole window for that, under
/// its controls, made the rescue window flicker four times a second (2026-11-09). A control
/// that moves has the area it leaves repainted by Windows itself.
fn store_cards(key: isize, cards: Vec<Rect>) -> bool {
    CARDS.with(|map| {
        let mut map = map.borrow_mut();
        if map.get(&key) == Some(&cards) {
            false
        } else {
            map.insert(key, cards);
            true
        }
    })
}

pub fn forget_window(hwnd: HWND) {
    CARDS.with(|map| map.borrow_mut().remove(&(hwnd as isize)));
}

/// Dark title bar and Windows 11 rounded frame where the OS supports them.
pub fn style_frame(hwnd: HWND) {
    let dark = i32::from(!current().high_contrast);
    let corners = 2i32;
    unsafe {
        DwmSetWindowAttribute(hwnd, 20, &dark as *const _ as *const _, 4);
        DwmSetWindowAttribute(hwnd, 33, &corners as *const _ as *const _, 4);
    }
}

/// WM_PAINT for a top-level window: page colour and rounded cards, double-buffered.
pub fn paint_surface(hwnd: HWND) {
    let mut ps: PAINTSTRUCT = unsafe { std::mem::zeroed() };
    let dc = unsafe { BeginPaint(hwnd, &mut ps) };
    let mut client = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    unsafe { GetClientRect(hwnd, &mut client) };
    let colors = current();
    let dpi = dpi_of(hwnd);
    buffered(dc, &client, |memory| {
        fill_rect(memory, &client, colors.page);
        let cards = CARDS.with(|map| map.borrow().get(&(hwnd as isize)).cloned());
        let radius = scale(dpi, grid::CARD_RADIUS) as f32;
        let line = scale(dpi, 1) as f32;
        if let Some(canvas) = Canvas::new(memory) {
            for card in cards.unwrap_or_default() {
                let r = (card.x as f32, card.y as f32, card.w as f32, card.h as f32);
                canvas.fill_round(r, radius, colors.card);
                canvas.stroke_round(r, radius, colors.border, line);
            }
        } else {
            for card in cards.unwrap_or_default() {
                let rect = RECT {
                    left: card.x,
                    top: card.y,
                    right: card.right(),
                    bottom: card.bottom(),
                };
                fill_rect(memory, &rect, colors.card);
            }
        }
    });
    unsafe { EndPaint(hwnd, &ps) };
}

/// `buffered` for a rectangle that does not start at the control's origin, such as one item
/// of a list: `paint` gets a rectangle starting at 0,0. GDI+ ignores a viewport offset for
/// the GDI calls made while it holds the device context, so text would land outside.
pub(crate) fn buffered_at_origin(dc: HDC, rect: &RECT, paint: impl FnOnce(HDC, &RECT)) {
    let local = RECT {
        left: 0,
        top: 0,
        right: rect.right - rect.left,
        bottom: rect.bottom - rect.top,
    };
    if local.right <= 0 || local.bottom <= 0 {
        return;
    }
    unsafe {
        let memory = CreateCompatibleDC(dc);
        let bitmap = CreateCompatibleBitmap(dc, local.right, local.bottom);
        let old = SelectObject(memory, bitmap);
        paint(memory, &local);
        BitBlt(
            dc,
            rect.left,
            rect.top,
            local.right,
            local.bottom,
            memory,
            0,
            0,
            SRCCOPY,
        );
        SelectObject(memory, old);
        DeleteObject(bitmap);
        DeleteDC(memory);
    }
}

/// Paints into an off-screen bitmap and copies it once, so updates never flicker.
pub(crate) fn buffered(dc: HDC, rect: &RECT, paint: impl FnOnce(HDC)) {
    let w = rect.right - rect.left;
    let h = rect.bottom - rect.top;
    if w <= 0 || h <= 0 {
        return;
    }
    unsafe {
        let memory = CreateCompatibleDC(dc);
        let bitmap = CreateCompatibleBitmap(dc, w, h);
        let old = SelectObject(memory, bitmap);
        SetViewportOrgEx(memory, -rect.left, -rect.top, std::ptr::null_mut());
        paint(memory);
        SetViewportOrgEx(memory, 0, 0, std::ptr::null_mut());
        BitBlt(dc, rect.left, rect.top, w, h, memory, 0, 0, SRCCOPY);
        SelectObject(memory, old);
        DeleteObject(bitmap);
        DeleteDC(memory);
    }
}

// ---------------------------------------------------------------- drawing

/// Spinner angle for running rows, advanced by the window's animation timer.
pub static SPIN: AtomicI32 = AtomicI32::new(0);

/// WM_DRAWITEM for every owner-drawn control.
pub fn draw_item(l: LPARAM) -> LRESULT {
    if l == 0 {
        return 0;
    }
    let item = unsafe { &*(l as *const DRAWITEMSTRUCT) };
    let hwnd = item.hwndItem;
    let word = style_word(hwnd);
    let colors = current();
    let dpi = dpi_of(hwnd);
    let fonts = fonts(dpi);
    let s = |v: i32| scale(dpi, v);
    let surface = if word & ON_CARD != 0 {
        colors.card
    } else {
        colors.page
    };
    let text = window_text(hwnd);
    let rect = item.rcItem;
    let (w, h) = (rect.right - rect.left, rect.bottom - rect.top);
    let state = item.itemState;
    buffered(item.hDC, &rect, |dc| {
        fill_rect(dc, &rect, surface);
        let canvas = Canvas::new(dc);
        let inner = |left: i32, right: i32| RECT {
            left: rect.left + left,
            top: rect.top,
            right: rect.right - right,
            bottom: rect.bottom,
        };
        match kind_of(word) {
            k if k == Kind::Title as u8 => draw_text(
                dc,
                &text,
                &rect,
                fonts.title,
                colors.text,
                DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS,
            ),
            k if k == Kind::Heading as u8 => draw_text(
                dc,
                &text,
                &rect,
                fonts.strong,
                colors.text,
                DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS,
            ),
            k if k == Kind::Body as u8 || k == Kind::Muted as u8 => {
                let color = match tone_of(word) {
                    Tone::Warn => colors.warn,
                    _ if k == Kind::Body as u8 => colors.text,
                    _ => colors.muted,
                };
                draw_text(dc, &text, &rect, fonts.body, color, DT_WORDBREAK);
            }
            k if k == Kind::Caption as u8 => {
                let format = if tone_of(word) == Tone::Neutral {
                    DT_LEFT
                } else {
                    DT_RIGHT
                };
                draw_text(
                    dc,
                    &text,
                    &rect,
                    fonts.caption,
                    colors.subtle,
                    format | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS,
                );
            }
            k if k == Kind::Bullet as u8 => {
                let cy = (rect.top + s(10)) as f32;
                let cx = (rect.left + s(8)) as f32;
                if let Some(canvas) = &canvas {
                    match tone_of(word) {
                        Tone::Yes => check_mark(canvas, cx, cy, s(5) as f32, colors.ok, s(2)),
                        Tone::No => cross(canvas, cx, cy, s(4) as f32, colors.subtle, s(2)),
                        _ => canvas.circle(cx, cy, s(2) as f32, colors.muted),
                    }
                }
                let body = RECT {
                    left: rect.left + s(24),
                    ..rect
                };
                draw_text(dc, &text, &body, fonts.body, colors.text, DT_WORDBREAK);
            }
            k if k == Kind::Row as u8 => draw_row(
                dc,
                canvas.as_ref(),
                &rect,
                &text,
                tone_of(word),
                RowLook {
                    first: word & FIRST != 0,
                    link: word & LINK != 0,
                    hot: word & HOT != 0,
                    focus: state & ODS_FOCUS != 0 && state & ODS_NOFOCUSRECT == 0,
                },
                &colors,
                &fonts,
                dpi,
            ),
            k if k == Kind::Pair as u8 => {
                let (key, value) = text.split_once(": ").unwrap_or(("", &text));
                let split = rect.left + s(132);
                let key_rect = RECT {
                    right: split - s(12),
                    ..inner(0, 0)
                };
                let value_rect = RECT {
                    left: split,
                    ..rect
                };
                draw_text(dc, key, &key_rect, fonts.body, colors.muted, DT_WORDBREAK);
                draw_text(
                    dc,
                    value,
                    &value_rect,
                    fonts.body,
                    colors.text,
                    DT_WORDBREAK,
                );
            }
            k if k == Kind::Badge as u8 => {
                let tone = tone_of(word);
                let (fill, dot, ink) = match tone {
                    Tone::Ok => (colors.border, colors.ok, colors.text),
                    Tone::Warn => (colors.border, colors.warn, colors.text),
                    Tone::Serious => (colors.border, colors.serious, colors.text),
                    Tone::Running => (colors.border, colors.text, colors.text),
                    _ => (colors.border, colors.subtle, colors.muted),
                };
                if let Some(canvas) = &canvas {
                    let r = (rect.left as f32, rect.top as f32, w as f32, h as f32);
                    canvas.fill_round(r, h as f32 / 2.0, fill);
                    canvas.circle(
                        (rect.left + s(12)) as f32,
                        (rect.top + h / 2) as f32,
                        s(3) as f32,
                        dot,
                    );
                }
                let label = RECT {
                    left: rect.left + s(22),
                    ..rect
                };
                draw_text(
                    dc,
                    &text,
                    &label,
                    fonts.caption,
                    ink,
                    DT_SINGLELINE | DT_VCENTER,
                );
            }
            k if k == Kind::Tile as u8 => {
                let (label, value) = text.split_once('\n').unwrap_or((&text, ""));
                let dot = match tone_of(word) {
                    Tone::Ok => Some(colors.ok),
                    Tone::Warn => Some(colors.warn),
                    Tone::Serious => Some(colors.serious),
                    _ => None,
                };
                let pad = s(12);
                if let Some(canvas) = &canvas {
                    let r = (rect.left as f32, rect.top as f32, w as f32, h as f32);
                    let radius = s(8) as f32;
                    canvas.fill_round(r, radius, colors.card);
                    canvas.stroke_round(r, radius, colors.border, s(1) as f32);
                    if let Some(dot) = dot {
                        canvas.circle(
                            (rect.right - pad) as f32,
                            (rect.top + s(18)) as f32,
                            s(4) as f32,
                            dot,
                        );
                    }
                }
                let top = RECT {
                    left: rect.left + pad,
                    top: rect.top + s(8),
                    right: rect.right - pad - s(10),
                    bottom: rect.top + s(28),
                };
                draw_text(
                    dc,
                    label,
                    &top,
                    fonts.caption,
                    colors.muted,
                    DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS,
                );
                let bottom = RECT {
                    left: rect.left + pad,
                    top: rect.top + s(28),
                    right: rect.right - pad,
                    bottom: rect.bottom - s(6),
                };
                // An Unavailable tone dims the value: it was not read.
                let ink = if tone_of(word) == Tone::Unavailable {
                    colors.subtle
                } else {
                    colors.text
                };
                draw_text(
                    dc,
                    value,
                    &bottom,
                    fonts.strong,
                    ink,
                    DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS,
                );
            }
            k if k == Kind::Progress as u8 => {
                let permille = ((word >> 20) & 0x7FF) as i32;
                if let Some(canvas) = &canvas {
                    let r = h as f32 / 2.0;
                    canvas.fill_round(
                        (rect.left as f32, rect.top as f32, w as f32, h as f32),
                        r,
                        colors.border,
                    );
                    let filled = (w * permille / 1000).max(if permille > 0 { h } else { 0 });
                    if filled > 0 {
                        canvas.fill_round(
                            (rect.left as f32, rect.top as f32, filled as f32, h as f32),
                            r,
                            colors.text,
                        );
                    }
                }
            }
            k if k == Kind::Icon as u8 => {
                if let Some(canvas) = &canvas {
                    let size = w.min(h) as f32;
                    let r = (rect.left as f32, rect.top as f32, size, size);
                    canvas.fill_round(r, size * 0.22, colors.raised);
                    let x = rect.left as f32;
                    let y = rect.top as f32;
                    let pts = [
                        (0.18, 0.55),
                        (0.36, 0.55),
                        (0.44, 0.42),
                        (0.54, 0.74),
                        (0.64, 0.28),
                        (0.72, 0.55),
                        (0.80, 0.55),
                    ]
                    .map(|(px, py)| (x + px * size, y + py * size));
                    canvas.polyline(&pts, colors.text, size * 0.07);
                    canvas.circle(x + 0.82 * size, y + 0.55 * size, size * 0.06, colors.ok);
                }
            }
            _ => draw_button(
                dc,
                canvas.as_ref(),
                &rect,
                &text,
                word,
                state,
                &colors,
                &fonts,
                dpi,
            ),
        }
    });
    1
}

pub(crate) fn check_mark(canvas: &Canvas, cx: f32, cy: f32, r: f32, color: u32, width: i32) {
    canvas.polyline(
        &[
            (cx - r, cy),
            (cx - r * 0.3, cy + r * 0.7),
            (cx + r, cy - r * 0.7),
        ],
        color,
        width as f32,
    );
}

pub(crate) fn cross(canvas: &Canvas, cx: f32, cy: f32, r: f32, color: u32, width: i32) {
    canvas.polyline(&[(cx - r, cy - r), (cx + r, cy + r)], color, width as f32);
    canvas.polyline(&[(cx - r, cy + r), (cx + r, cy - r)], color, width as f32);
}

/// How a result row is drawn beyond its tone.
#[derive(Clone, Copy)]
struct RowLook {
    first: bool,
    /// Opens a tool: a chevron, and a highlight under the pointer.
    link: bool,
    hot: bool,
    focus: bool,
}

#[allow(clippy::too_many_arguments)]
fn draw_row(
    dc: HDC,
    canvas: Option<&Canvas>,
    rect: &RECT,
    text: &str,
    tone: Tone,
    look: RowLook,
    colors: &Palette,
    fonts: &Fonts,
    dpi: u32,
) {
    let s = |v: i32| scale(dpi, v);
    let (label, brief) = text.split_once(": ").unwrap_or((text, ""));
    let first = look.first;
    if let Some(canvas) = canvas {
        let body = (
            rect.left as f32,
            (rect.top + s(2)) as f32,
            (rect.right - rect.left) as f32,
            (rect.bottom - rect.top - s(3)) as f32,
        );
        if look.link && look.hot {
            canvas.fill_round(body, s(6) as f32, colors.raised);
        }
        if look.focus {
            canvas.stroke_round(body, s(6) as f32, colors.ring, s(2) as f32);
        }
        if look.link {
            let cx = (rect.right - s(10)) as f32;
            let cy = ((rect.top + rect.bottom) / 2) as f32;
            let r = s(4) as f32;
            let color = if look.hot { colors.text } else { colors.subtle };
            canvas.polyline(
                &[
                    (cx - r * 0.5, cy - r),
                    (cx + r * 0.5, cy),
                    (cx - r * 0.5, cy + r),
                ],
                color,
                s(2) as f32,
            );
        }
    }
    if !first {
        let line = RECT {
            left: rect.left + s(4),
            top: rect.top,
            right: rect.right - s(4),
            bottom: rect.top + s(1).max(1),
        };
        fill_rect(dc, &line, colors.border);
    }
    let cx = (rect.left + s(14)) as f32;
    let cy = ((rect.top + rect.bottom) / 2) as f32;
    let r = s(8) as f32;
    let stroke = s(2) as f32;
    if let Some(canvas) = canvas {
        match tone {
            Tone::Ok => {
                canvas.circle(cx, cy, r, colors.ok);
                check_mark(
                    canvas,
                    cx,
                    cy + s(1) as f32 * 0.0,
                    r * 0.45,
                    colors.card,
                    s(2),
                );
            }
            Tone::Flag | Tone::Serious => {
                let fill = if tone == Tone::Serious {
                    colors.serious
                } else {
                    colors.warn
                };
                canvas.circle(cx, cy, r, fill);
                canvas.polyline(
                    &[(cx, cy - r * 0.45), (cx, cy + r * 0.1)],
                    colors.card,
                    stroke,
                );
                canvas.circle(cx, cy + r * 0.45, stroke * 0.6, colors.card);
                if tone == Tone::Serious && colors.high_contrast {
                    // A second ring tells serious from flagged when both are one colour.
                    canvas.arc((cx, cy, r + stroke * 1.5), 0.0, 360.0, fill, stroke * 0.75);
                }
            }
            Tone::Unavailable => {
                canvas.arc(
                    (cx, cy, r - stroke / 2.0),
                    0.0,
                    360.0,
                    colors.warn,
                    stroke * 0.75,
                );
                canvas.polyline(
                    &[(cx - r * 0.4, cy), (cx + r * 0.4, cy)],
                    colors.warn,
                    stroke,
                );
            }
            Tone::Running => {
                canvas.arc(
                    (cx, cy, r - stroke / 2.0),
                    0.0,
                    360.0,
                    colors.border,
                    stroke,
                );
                let start = SPIN.load(Ordering::Relaxed) as f32;
                canvas.arc(
                    (cx, cy, r - stroke / 2.0),
                    start,
                    100.0,
                    colors.text,
                    stroke,
                );
            }
            Tone::NotRun => canvas.polyline(
                &[(cx - r * 0.5, cy), (cx + r * 0.5, cy)],
                colors.subtle,
                stroke,
            ),
            _ => canvas.arc(
                (cx, cy, r - stroke / 2.0),
                0.0,
                360.0,
                colors.raised_hover,
                stroke * 0.75,
            ),
        }
    }
    let label_color = match tone {
        Tone::Waiting | Tone::NotRun => colors.muted,
        _ => colors.text,
    };
    let brief_color = match tone {
        Tone::Flag | Tone::Unavailable if !colors.high_contrast => colors.warn,
        Tone::Serious if !colors.high_contrast => colors.serious,
        Tone::NotRun | Tone::Waiting => colors.subtle,
        _ => colors.muted,
    };
    let label_rect = RECT {
        left: rect.left + s(grid::ROW_LABEL_X),
        right: rect.left + s(grid::ROW_LABEL_X) + s(grid::ROW_LABEL_W),
        ..*rect
    };
    draw_text(
        dc,
        label,
        &label_rect,
        fonts.body,
        label_color,
        DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS,
    );
    let chevron = if look.link { s(16) } else { 0 };
    let brief_rect = RECT {
        left: label_rect.right + s(grid::ROW_TEXT_GAP),
        right: rect.right - s(grid::ROW_TEXT_GAP) - chevron,
        ..*rect
    };
    draw_text(
        dc,
        brief,
        &brief_rect,
        fonts.body,
        brief_color,
        DT_SINGLELINE | DT_VCENTER | DT_RIGHT | DT_END_ELLIPSIS,
    );
}

/// Mixes `a` toward `b`, keeping `keep` thousandths of `a`, channel by channel.
const fn mix(a: u32, b: u32, keep: u32) -> u32 {
    let mut out = 0;
    let mut shift = 0;
    while shift < 24 {
        let (x, y) = ((a >> shift) & 0xFF, (b >> shift) & 0xFF);
        out |= ((x * keep + y * (1000 - keep) + 500) / 1000) << shift;
        shift += 8;
    }
    out
}

/// How much of its enabled look a disabled button keeps against its surface.
const DISABLED_KEEP: u32 = 400;

/// A button's fill, border and ink. A disabled button fades toward the surface, so it reads
/// as switched off for every kind: a filled one becomes a faint outlined box with dim words
/// (the primary one too, so it never looks brighter than an enabled button), and a text-only
/// one keeps no more than dim words.
fn button_look(
    kind: u8,
    hot: bool,
    disabled: bool,
    colors: &Palette,
    surface: u32,
) -> (Option<u32>, Option<u32>, u32) {
    let hot = hot && !disabled;
    let kind = if disabled && kind == Kind::Primary as u8 {
        Kind::Secondary as u8
    } else {
        kind
    };
    let (fill, border, ink) = if kind == Kind::Primary as u8 {
        let fill = if hot {
            colors.primary_hover
        } else {
            colors.primary
        };
        (Some(fill), None, colors.primary_text)
    } else if kind == Kind::Secondary as u8 {
        let fill = if hot {
            colors.raised_hover
        } else {
            colors.raised
        };
        (Some(fill), Some(colors.raised_hover), colors.text)
    } else {
        let fill = hot.then_some(colors.raised);
        (fill, None, if hot { colors.text } else { colors.muted })
    };
    if !disabled {
        return (fill, border, ink);
    }
    if colors.high_contrast {
        // System colours: GrayText is the user's own disabled colour.
        return (fill.map(|_| surface), border, colors.subtle);
    }
    let fade = |c: u32| mix(c, surface, DISABLED_KEEP);
    (fill.map(fade), border.map(fade), fade(ink))
}

#[allow(clippy::too_many_arguments)]
fn draw_button(
    dc: HDC,
    canvas: Option<&Canvas>,
    rect: &RECT,
    caption: &str,
    word: isize,
    state: u32,
    colors: &Palette,
    fonts: &Fonts,
    dpi: u32,
) {
    let s = |v: i32| scale(dpi, v);
    let hot = word & HOT != 0;
    let pressed = state & ODS_SELECTED != 0;
    let disabled = state & ODS_DISABLED != 0;
    let focused = state & ODS_FOCUS != 0 && state & ODS_NOFOCUSRECT == 0;
    let surface = if word & ON_CARD != 0 {
        colors.card
    } else {
        colors.page
    };
    let kind = kind_of(word);
    let (fill, border, ink) = button_look(kind, hot || pressed, disabled, colors, surface);
    let ring = s(2);
    let body = (
        (rect.left + ring) as f32,
        (rect.top + ring) as f32,
        (rect.right - rect.left - 2 * ring) as f32,
        (rect.bottom - rect.top - 2 * ring) as f32,
    );
    let radius = s(grid::BUTTON_RADIUS) as f32;
    if let Some(canvas) = canvas {
        if let Some(fill) = fill {
            canvas.fill_round(body, radius, fill);
        }
        if let Some(border) = border {
            canvas.stroke_round(body, radius, border, s(1) as f32);
        }
        if focused {
            let outer = (
                rect.left as f32,
                rect.top as f32,
                (rect.right - rect.left) as f32,
                (rect.bottom - rect.top) as f32,
            );
            canvas.stroke_round(outer, radius + ring as f32, colors.ring, ring as f32);
        }
    } else if let Some(fill) = fill {
        fill_rect(dc, rect, fill);
    }
    if kind == Kind::Update as u8 {
        // Arrow into a tray, then the caption, centred together.
        let icon = s(UPDATE_ICON);
        let gap = s(8);
        let text_w = text_width(std::ptr::null_mut(), fonts.strong, caption);
        let left = (rect.left + rect.right - (icon + gap + text_w)) / 2;
        if let Some(canvas) = canvas {
            let accent = if disabled { ink } else { colors.ok };
            let (x, cy) = (left as f32, ((rect.top + rect.bottom) / 2) as f32);
            let size = icon as f32;
            let stroke = s(2) as f32;
            let mid = x + size / 2.0;
            let (top, tip) = (cy - size * 0.5, cy + size * 0.15);
            canvas.polyline(&[(mid, top), (mid, tip)], accent, stroke);
            canvas.polyline(
                &[
                    (mid - size * 0.3, tip - size * 0.3),
                    (mid, tip),
                    (mid + size * 0.3, tip - size * 0.3),
                ],
                accent,
                stroke,
            );
            canvas.polyline(
                &[
                    (x, cy + size * 0.2),
                    (x, cy + size * 0.5),
                    (x + size, cy + size * 0.5),
                    (x + size, cy + size * 0.2),
                ],
                accent,
                stroke,
            );
        }
        let text_rect = RECT {
            left: left + icon + gap,
            ..*rect
        };
        draw_text(
            dc,
            caption,
            &text_rect,
            fonts.strong,
            ink,
            DT_SINGLELINE | DT_VCENTER | DT_LEFT,
        );
        return;
    }
    // A caption wider than its button, such as a long folder, loses its middle, not its ends.
    draw_text(
        dc,
        caption,
        rect,
        fonts.strong,
        ink,
        DT_SINGLELINE | DT_VCENTER | DT_CENTER | DT_PATH_ELLIPSIS,
    );
}

/// Width of the update button's arrow, before the gap to its caption.
pub const UPDATE_ICON: i32 = 14;

#[cfg(test)]
mod tests {

    /// The guard: setting the cards a window already has repaints nothing; changed cards
    /// repaint it.
    #[test]
    fn the_same_cards_repaint_nothing() {
        let card = |h| Rect {
            x: 0,
            y: 0,
            w: 100,
            h,
        };
        let key = 0x5EED;
        assert!(store_cards(key, vec![card(40)]), "the first cards");
        assert!(!store_cards(key, vec![card(40)]), "the same again");
        assert!(store_cards(key, vec![card(48)]), "a card grew");
        assert!(!store_cards(key, vec![card(48)]));
        assert!(store_cards(key, Vec::new()), "the cards gone");
    }
    use super::*;

    /// A shown control in a window not yet on screen counts as shown, so a page measured
    /// before its window appears keeps its buttons' rows.
    #[test]
    fn a_shown_control_counts_before_its_window_is_on_screen() {
        unsafe {
            let parent = CreateWindowExW(
                0,
                wide("STATIC").as_ptr(),
                std::ptr::null(),
                WS_POPUP,
                0,
                0,
                100,
                100,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
            );
            assert!(!parent.is_null());
            let child = CreateWindowExW(
                0,
                wide("STATIC").as_ptr(),
                std::ptr::null(),
                WS_CHILD | WS_VISIBLE,
                0,
                0,
                10,
                10,
                parent,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
            );
            assert!(!child.is_null());
            assert!(visible(child));
            show(child, false);
            assert!(!visible(child));
            DestroyWindow(parent);
        }
    }

    /// Grey level of a COLORREF, 0 to 255.
    fn level(c: u32) -> i32 {
        let (r, g, b) = (c & 0xFF, (c >> 8) & 0xFF, (c >> 16) & 0xFF);
        ((r * 299 + g * 587 + b * 114) / 1000) as i32
    }

    /// The part of a button that stands out from its surface: the fill when it has one,
    /// else the ink.
    fn standout(look: (Option<u32>, Option<u32>, u32), surface: u32) -> i32 {
        (level(look.0.unwrap_or(look.2)) - level(surface)).abs()
    }

    /// Every kind of button, on the page and on a card, keeps at most half its contrast
    /// with the surface when disabled, so enabled and disabled are told apart at a glance.
    #[test]
    fn a_disabled_button_of_every_kind_is_plainly_dimmer() {
        let colors = DARK;
        for surface in [colors.page, colors.card] {
            for kind in [Kind::Primary, Kind::Secondary, Kind::Ghost, Kind::Update] {
                let on = button_look(kind as u8, false, false, &colors, surface);
                let off = button_look(kind as u8, false, true, &colors, surface);
                let (on, off) = (standout(on, surface), standout(off, surface));
                assert!(off * 2 <= on, "{kind:?}: enabled {on}, disabled {off}");
                // Still readable: a disabled caption stands out from what it sits on.
                let (fill, _, ink) = button_look(kind as u8, false, true, &colors, surface);
                let under = fill.unwrap_or(surface);
                assert!((level(ink) - level(under)).abs() >= 40, "{kind:?}");
            }
        }
    }

    /// A disabled main button never stands out more than an enabled ordinary one, so it is
    /// not taken for the button to press.
    #[test]
    fn a_disabled_primary_button_is_no_brighter_than_an_enabled_secondary() {
        let colors = DARK;
        let surface = colors.page;
        let off = button_look(Kind::Primary as u8, false, true, &colors, surface);
        let on = button_look(Kind::Secondary as u8, false, false, &colors, surface);
        assert!(standout(off, surface) <= standout(on, surface));
    }

    #[test]
    fn hovering_a_disabled_button_does_not_light_it() {
        let colors = DARK;
        let still = button_look(Kind::Ghost as u8, false, true, &colors, colors.page);
        let hovered = button_look(Kind::Ghost as u8, true, true, &colors, colors.page);
        assert_eq!(still, hovered);
    }
}
