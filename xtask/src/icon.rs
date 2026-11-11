//! Renders the application icon: a zinc rounded square with a white pulse line
//! ending in an emerald dot, written as a multi-size ICO.

use std::io;

const FILL: [f32; 3] = rgb(0x18181b);
const EDGE: [f32; 3] = rgb(0x3f3f46);
const LINE: [f32; 3] = rgb(0xfafafa);
const DOT: [f32; 3] = rgb(0x34d399);

/// Sizes stored as 32-bit BMP entries; 256 is stored as PNG.
pub const BMP_SIZES: [u32; 7] = [16, 20, 24, 32, 40, 48, 64];
pub const PNG_SIZE: u32 = 256;

// The pulse in units of the square's side: flat, small rise, tall spike, dip, flat.
// The dot sits on the last point.
const PULSE: [(f32, f32); 8] = [
    (0.14, 0.56),
    (0.30, 0.56),
    (0.36, 0.46),
    (0.42, 0.56),
    (0.50, 0.21),
    (0.59, 0.77),
    (0.66, 0.56),
    (0.80, 0.56),
];

// Below this size the small rise is under two pixels and only blurs the spike.
const SMALL_RISE_MIN_SIZE: u32 = 24;

const fn rgb(hex: u32) -> [f32; 3] {
    [
        ((hex >> 16) & 0xff) as f32 / 255.0,
        ((hex >> 8) & 0xff) as f32 / 255.0,
        (hex & 0xff) as f32 / 255.0,
    ]
}

struct Geometry {
    centre: f32,
    half: f32,
    radius: f32,
    edge: f32,
    stroke: f32,
    dot: f32,
    points: Vec<(f32, f32)>,
}

impl Geometry {
    fn new(size: u32) -> Self {
        let s = size as f32;
        // Whole-pixel margin keeps the square's straight edges crisp at small sizes.
        let margin = (s * 0.03).round();
        let side = s - 2.0 * margin;
        // Whole-pixel strokes up to 64 px keep the flat runs sharp.
        let stroke = if size <= 64 {
            (s * 0.065).round().max(1.0)
        } else {
            s * 0.065
        };
        let mut points: Vec<(f32, f32)> = PULSE
            .iter()
            .enumerate()
            .filter(|&(i, _)| size >= SMALL_RISE_MIN_SIZE || !(2..=3).contains(&i))
            .map(|(_, &(x, y))| (margin + x * side, margin + y * side))
            .collect();
        // Centre the flat runs on a pixel row (odd stroke) or boundary (even) so they stay sharp.
        let baseline = points[0].1;
        let snapped = if stroke.round() as u32 % 2 == 1 {
            baseline.floor() + 0.5
        } else {
            baseline.round()
        };
        for p in &mut points {
            p.1 += snapped - baseline;
        }
        Geometry {
            centre: s / 2.0,
            half: side / 2.0,
            radius: side * 0.22,
            edge: (s / 128.0).max(1.0),
            stroke,
            dot: (stroke * 1.2).max(1.6),
            points,
        }
    }

    fn square_distance(&self, x: f32, y: f32) -> f32 {
        let inner = self.half - self.radius;
        let qx = (x - self.centre).abs() - inner;
        let qy = (y - self.centre).abs() - inner;
        let outside = qx.max(0.0).hypot(qy.max(0.0));
        outside + qx.max(qy).min(0.0) - self.radius
    }

    fn line_distance(&self, x: f32, y: f32) -> f32 {
        self.points
            .windows(2)
            .map(|w| segment_distance((x, y), w[0], w[1]))
            .fold(f32::INFINITY, f32::min)
    }

    fn colour_at(&self, x: f32, y: f32) -> Option<[f32; 3]> {
        let d = self.square_distance(x, y);
        if d > 0.0 {
            return None;
        }
        let end = self.points[self.points.len() - 1];
        if (x - end.0).hypot(y - end.1) <= self.dot {
            return Some(DOT);
        }
        if self.line_distance(x, y) <= self.stroke / 2.0 {
            return Some(LINE);
        }
        Some(if d > -self.edge { EDGE } else { FILL })
    }
}

fn segment_distance(p: (f32, f32), a: (f32, f32), b: (f32, f32)) -> f32 {
    let (dx, dy) = (b.0 - a.0, b.1 - a.1);
    let t = (((p.0 - a.0) * dx + (p.1 - a.1) * dy) / (dx * dx + dy * dy)).clamp(0.0, 1.0);
    (p.0 - a.0 - t * dx).hypot(p.1 - a.1 - t * dy)
}

/// Straight (non-premultiplied) RGBA rows, top to bottom, anti-aliased by supersampling.
pub fn render(size: u32) -> Vec<u8> {
    let geometry = Geometry::new(size);
    let grid = 16u32;
    let samples = (grid * grid) as f32;
    let mut out = Vec::with_capacity((size * size * 4) as usize);
    for py in 0..size {
        for px in 0..size {
            let mut acc = [0.0f32; 4];
            for sy in 0..grid {
                for sx in 0..grid {
                    let x = px as f32 + (sx as f32 + 0.5) / grid as f32;
                    let y = py as f32 + (sy as f32 + 0.5) / grid as f32;
                    if let Some(c) = geometry.colour_at(x, y) {
                        acc[0] += c[0];
                        acc[1] += c[1];
                        acc[2] += c[2];
                        acc[3] += 1.0;
                    }
                }
            }
            if acc[3] == 0.0 {
                out.extend_from_slice(&[0, 0, 0, 0]);
                continue;
            }
            for channel in &acc[..3] {
                out.push((channel / acc[3] * 255.0).round() as u8);
            }
            out.push((acc[3] / samples * 255.0).round() as u8);
        }
    }
    out
}

pub fn png(size: u32, rgba: &[u8]) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut encoder = png::Encoder::new(&mut bytes, size, size);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    encoder.set_compression(png::Compression::High);
    let mut writer = encoder.write_header().map_err(io::Error::other)?;
    writer.write_image_data(rgba).map_err(io::Error::other)?;
    writer.finish().map_err(io::Error::other)?;
    Ok(bytes)
}

// A 32-bit DIB entry: BITMAPINFOHEADER, BGRA rows bottom-up, then the 1-bit AND mask.
fn bmp_entry(size: u32, rgba: &[u8]) -> Vec<u8> {
    let mask_stride = size.div_ceil(32) * 4;
    let mut out = Vec::new();
    for v in [40u32, size, size * 2] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    let image_size = size * size * 4 + mask_stride * size;
    for v in [0u32, image_size, 0, 0, 0, 0] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    for row in (0..size).rev() {
        for col in 0..size {
            let i = ((row * size + col) * 4) as usize;
            out.extend_from_slice(&[rgba[i + 2], rgba[i + 1], rgba[i], rgba[i + 3]]);
        }
    }
    for row in (0..size).rev() {
        let mut mask = vec![0u8; mask_stride as usize];
        for col in 0..size {
            if rgba[((row * size + col) * 4 + 3) as usize] == 0 {
                mask[(col / 8) as usize] |= 0x80 >> (col % 8);
            }
        }
        out.extend_from_slice(&mask);
    }
    out
}

/// The complete ICO file with every size.
pub fn ico() -> io::Result<Vec<u8>> {
    let mut images: Vec<(u32, Vec<u8>)> = BMP_SIZES
        .iter()
        .map(|&s| (s, bmp_entry(s, &render(s))))
        .collect();
    images.push((PNG_SIZE, png(PNG_SIZE, &render(PNG_SIZE))?));

    let mut out = Vec::new();
    for v in [0u16, 1, images.len() as u16] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    let mut offset = 6 + 16 * images.len() as u32;
    for (size, data) in &images {
        // A dimension of 256 is stored as 0.
        let dim = if *size >= 256 { 0 } else { *size as u8 };
        out.extend_from_slice(&[dim, dim, 0, 0]);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        offset += data.len() as u32;
    }
    for (_, data) in &images {
        out.extend_from_slice(data);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corners_are_transparent_and_centre_is_filled() {
        let size = 32;
        let px = render(size);
        assert_eq!(px[3], 0, "top-left corner is outside the rounded square");
        let at = |x: u32, y: u32| &px[((y * size + x) * 4) as usize..][..4];
        assert_eq!(
            at(8, 26),
            &[0x18, 0x18, 0x1b, 0xff],
            "lower body is the fill colour"
        );
    }

    #[test]
    fn ico_directory_lists_every_size_at_its_offset() {
        let ico = ico().unwrap();
        let count = u16::from_le_bytes([ico[4], ico[5]]) as usize;
        assert_eq!(count, BMP_SIZES.len() + 1);
        for i in 0..count {
            let entry = &ico[6 + i * 16..][..16];
            let len = u32::from_le_bytes(entry[8..12].try_into().unwrap()) as usize;
            let offset = u32::from_le_bytes(entry[12..16].try_into().unwrap()) as usize;
            assert!(offset + len <= ico.len());
            let png_magic = &ico[offset..offset + 4] == b"\x89PNG";
            assert_eq!(png_magic, entry[0] == 0, "only the 256 entry is PNG");
        }
    }
}
