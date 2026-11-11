//! Hang zones: the places a drive hung (dropped off the bus) in a rescue, and the span set
//! aside around each. A zone changes no status in the map; it only orders the reads. Each
//! phase reads everything outside the zones first, then each zone from the side away from
//! its hangs, and leaves a zone as it is once the drive has hung there `BUDGET` times in the
//! phase (two per zone).

use super::image::{Phase, DROP_SKIP_SHARE};

/// Hangs allowed in one zone in one phase, the one that made the zone included.
pub const BUDGET: u32 = 2;

/// One zone: `from..to`, the reads in flight when the drive hung there, and the hangs spent
/// in the current phase.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Zone {
    pub from: u64,
    pub to: u64,
    /// The reads the drive hung in, sorted and apart.
    pub hangs: Vec<(u64, u64)>,
    /// Hangs in this zone in the current phase.
    pub spent: u32,
}

/// A stretch of a zone between its hangs, read from one end towards the other: downwards
/// (from `to` towards `from`) when `down`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stretch {
    pub from: u64,
    pub to: u64,
    pub down: bool,
}

/// A run's zones, kept for the app session (`Remembered`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Zones {
    list: Vec<Zone>,
    /// The phase the budgets count in.
    phase: Option<Phase>,
}

impl Zones {
    pub fn list(&self) -> &[Zone] {
        &self.list
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Starts `phase`'s budgets: every zone gets `BUDGET` hangs again in a new phase. True
    /// when `phase` is new.
    pub fn start_phase(&mut self, phase: Phase) -> bool {
        if self.phase == Some(phase) {
            return false;
        }
        self.phase = Some(phase);
        for zone in &mut self.list {
            zone.spent = 0;
        }
        true
    }

    /// Sizes every zone afresh to the damaged area around each of its hangs (`area` of a
    /// hang's read), keeping the hangs and what each zone has spent: what an earlier phase
    /// set aside ahead of a hang, or an area since read, is no longer kept apart.
    pub fn fit(&mut self, area: impl Fn(u64, u64) -> (u64, u64)) {
        let mut fitted = Vec::new();
        for zone in self.list.drain(..) {
            for (i, &(at, end)) in zone.hangs.iter().enumerate() {
                let (lo, hi) = area(at, end);
                fitted.push(Zone {
                    from: lo.min(at),
                    to: hi.max(end),
                    hangs: vec![(at, end)],
                    spent: if i == 0 { zone.spent } else { 0 },
                });
            }
        }
        self.list = fitted;
        self.merge();
    }

    /// The first zone that overlaps `pos..end`.
    pub fn first_overlap(&self, pos: u64, end: u64) -> Option<&Zone> {
        self.list.iter().find(|z| z.from < end && pos < z.to)
    }

    /// The last zone that overlaps `pos..end`.
    pub fn last_overlap(&self, pos: u64, end: u64) -> Option<&Zone> {
        self.list.iter().rev().find(|z| z.from < end && pos < z.to)
    }

    /// Records that the drive hung in the read `at..at + len`, in the damaged `area` around
    /// it the map shows (`Map::area`), if any. Inside a zone, the hang joins it and the zone
    /// takes in the area. Elsewhere, a new zone sets aside the area, and with `ahead` (copying,
    /// which has nothing mapped ahead of it) also that many bytes in the direction the pass
    /// read (backwards: before the read), aligned to `sector`, at most `DROP_SKIP_SHARE` of
    /// the drive. Nothing doubles: each zone is as large as its own damage. Returns the span
    /// set aside.
    #[allow(clippy::too_many_arguments)]
    pub fn hang(
        &mut self,
        at: u64,
        len: u64,
        backwards: bool,
        size: u64,
        sector: u64,
        ahead: u64,
        area: Option<(u64, u64)>,
    ) -> (u64, u64) {
        let end = at.saturating_add(len).min(size);
        let (lo, hi) = area.map_or((at, end), |(lo, hi)| (lo.min(at), hi.max(end).min(size)));
        if let Some(zone) = self.list.iter_mut().find(|z| z.from <= at && at < z.to) {
            zone.from = zone.from.min(lo);
            zone.to = zone.to.max(hi);
            add_hang(&mut zone.hangs, (at, end));
            zone.spent += 1;
            let span = (zone.from, zone.to);
            self.merge();
            return span;
        }
        let sector = sector.max(1);
        let ahead = skip_ahead(ahead, size, sector);
        let span = if backwards {
            (lo.min(at.saturating_sub(ahead) / sector * sector), hi)
        } else {
            (lo, hi.max(at.saturating_add(ahead).min(size)))
        };
        self.list.push(Zone {
            from: span.0,
            to: span.1,
            hangs: vec![(at, end)],
            spent: 1,
        });
        self.merge();
        span
    }

    /// Adds a zone a run before this app session set aside, `from..to` around the read the
    /// drive hung in, with the whole budget of the phase still to spend.
    pub fn seed(&mut self, from: u64, to: u64, hang: (u64, u64)) {
        if from >= to {
            return;
        }
        let hang = (hang.0.clamp(from, to), hang.1.clamp(from, to));
        self.list.push(Zone {
            from,
            to,
            hangs: if hang.0 < hang.1 {
                vec![hang]
            } else {
                Vec::new()
            },
            spent: 0,
        });
        self.merge();
    }

    /// Joins zones that overlap or touch, keeping every hang and the hangs spent in both.
    fn merge(&mut self) {
        self.list.sort_by_key(|z| z.from);
        let mut merged: Vec<Zone> = Vec::with_capacity(self.list.len());
        for zone in self.list.drain(..) {
            match merged.last_mut() {
                Some(last) if zone.from <= last.to => {
                    last.to = last.to.max(zone.to);
                    for hang in zone.hangs {
                        add_hang(&mut last.hangs, hang);
                    }
                    last.spent += zone.spent;
                }
                _ => merged.push(zone),
            }
        }
        self.list = merged;
    }

    /// The stretches of the zones with hangs left in this phase, in order: each part of a
    /// zone between its hangs, read away from the hangs that bound it; a part with a hang at
    /// both ends is read from its middle (aligned to `unit`) outwards, as two stretches, the
    /// upper first, and not at all when it is shorter than two units. The hang places
    /// themselves follow, after every zone's parts.
    pub fn stretches(&self, unit: u64) -> Vec<Stretch> {
        let unit = unit.max(1);
        let mut out = Vec::new();
        let mut hung = Vec::new();
        for zone in self.list.iter().filter(|z| z.spent < BUDGET) {
            let mut at = zone.from;
            let mut hung_low = false;
            let mut parts = Vec::new();
            for &(h, e) in &zone.hangs {
                if h > at {
                    parts.push((at, h, hung_low, true));
                }
                at = at.max(e);
                hung_low = true;
            }
            if zone.to > at {
                parts.push((at, zone.to, hung_low, false));
            }
            for (from, to, low, high) in parts {
                match (low, high) {
                    // The first read is at the middle; a part too short to have a middle
                    // apart from both hangs is left as it is.
                    (true, true) => {
                        let mid = from + (to - from) / 2 / unit * unit;
                        if mid > from {
                            out.push(Stretch {
                                from: mid,
                                to,
                                down: false,
                            });
                            out.push(Stretch {
                                from,
                                to: mid,
                                down: true,
                            });
                        }
                    }
                    (true, false) => out.push(Stretch {
                        from,
                        to,
                        down: true,
                    }),
                    _ => out.push(Stretch {
                        from,
                        to,
                        down: false,
                    }),
                }
            }
            hung.extend(zone.hangs.iter().map(|&(from, to)| Stretch {
                from,
                to,
                down: false,
            }));
        }
        // The reads the drive hung in come last of all: a later phase reads them again, as
        // any failed read, once the rest of every zone is done.
        out.extend(hung);
        out
    }
}

/// What is set aside ahead of a drop where nothing is mapped yet: `first` aligned to
/// `sector`, at most `DROP_SKIP_SHARE` of the drive; none for a `first` of 0.
pub fn skip_ahead(first: u64, size: u64, sector: u64) -> u64 {
    if first == 0 {
        return 0;
    }
    let sector = sector.max(1);
    let cap = (size / DROP_SKIP_SHARE / sector * sector).max(sector);
    (first / sector * sector).clamp(sector, cap)
}

fn add_hang(hangs: &mut Vec<(u64, u64)>, hang: (u64, u64)) {
    hangs.push(hang);
    hangs.sort_unstable();
    let mut joined: Vec<(u64, u64)> = Vec::with_capacity(hangs.len());
    for (h, e) in hangs.drain(..) {
        match joined.last_mut() {
            Some(last) if h <= last.1 => last.1 = last.1.max(e),
            _ => joined.push((h, e)),
        }
    }
    *hangs = joined;
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;

    /// The guard: a
    /// zone is the damaged area around its hang, plus in copying the first skip ahead, the
    /// same for every drop; a drop next to a zone does not make the next one larger. On a
    /// failing drive the doubled skip reached 8.6 GB and put five damaged areas, 0.1 to
    /// 0.6 GB apart, in one zone with one budget.
    #[test]
    fn a_zone_is_its_damaged_area_and_never_doubles() {
        let len: u64 = 2_000_398_934_016;
        let cap = len / 20 / 512 * 512;
        let gib = 1u64 << 30;
        let mut zones = Zones::default();
        zones.start_phase(Phase::Copying);
        let mut at = 137_400_000_000;
        let mut skips = Vec::new();
        for _ in 0..4 {
            let (from, to) = zones.hang(at, 4096, false, len, 512, gib, None);
            skips.push(to - from);
            at = to;
        }
        assert_eq!(skips, [gib; 4]);
        assert_eq!(zones.list().len(), 1, "touching zones join");
        assert_eq!(
            zones.hang(at, 4096, false, len, 512, 2 * cap, None).1 - at,
            cap
        );
        // A backward pass sets aside the span before the read.
        let mut back = Zones::default();
        assert_eq!(
            back.hang(10 * MIB, 4096, true, len, 512, MIB, None),
            (9 * MIB, 10 * MIB + 4096)
        );
        // Trimming and scraping set aside the damaged area alone; copying the area and the
        // skip ahead of the read.
        let mut areas = Zones::default();
        areas.start_phase(Phase::Scraping);
        let area = Some((5 * MIB, 7 * MIB));
        assert_eq!(
            areas.hang(6 * MIB, 512, false, len, 512, 0, area),
            (5 * MIB, 7 * MIB)
        );
        assert_eq!(
            areas.hang(
                20 * MIB,
                512,
                false,
                len,
                512,
                MIB,
                Some((19 * MIB, 20 * MIB + 512))
            ),
            (19 * MIB, 21 * MIB)
        );
        // A hang inside takes in the area around it, and spends the zone's budget.
        assert_eq!(
            areas.hang(
                6 * MIB + 512,
                512,
                false,
                len,
                512,
                0,
                Some((4 * MIB, 7 * MIB))
            ),
            (4 * MIB, 7 * MIB)
        );
        assert_eq!(areas.list()[0].spent, 2);
        assert_eq!(areas.list().len(), 2, "areas apart stay apart");
    }

    /// The guard: a new phase sizes each zone to the damaged areas around its hangs, so a
    /// copying zone's skip ahead is no longer set aside, and zones whose areas meet join.
    #[test]
    fn a_new_phase_fits_the_zones_to_their_areas() {
        let len = 1024 * MIB;
        let mut zones = Zones::default();
        zones.start_phase(Phase::Copying);
        zones.hang(8 * MIB, 4096, false, len, 512, 256 * MIB, None);
        zones.hang(300 * MIB, 4096, false, len, 512, 256 * MIB, None);
        assert!(!zones.start_phase(Phase::Copying));
        assert!(zones.start_phase(Phase::Trimming));
        zones.fit(|at, end| (at - MIB, end + MIB));
        let got: Vec<(u64, u64)> = zones.list().iter().map(|z| (z.from, z.to)).collect();
        assert_eq!(
            got,
            [(7 * MIB, 9 * MIB + 4096), (299 * MIB, 301 * MIB + 4096)]
        );
        assert!(zones
            .list()
            .iter()
            .all(|z| z.spent == 0 && z.hangs.len() == 1));
    }

    /// The guard: each part of a zone is read away from the hangs that bound it; a part with
    /// hangs at both ends from its middle outwards; the hang places last; a zone whose budget
    /// is spent not at all, until the next phase gives it its budget again.
    #[test]
    fn a_zone_is_read_away_from_its_hangs_within_its_budget() {
        let len = 64 * MIB;
        let mut zones = Zones::default();
        zones.start_phase(Phase::Copying);
        zones.hang(8 * MIB, 4096, false, len, 512, MIB, None);
        assert_eq!(
            zones.stretches(512),
            [
                Stretch {
                    from: 8 * MIB + 4096,
                    to: 9 * MIB,
                    down: true
                },
                Stretch {
                    from: 8 * MIB,
                    to: 8 * MIB + 4096,
                    down: false
                }
            ]
        );
        // A second hang inside, at 8.5 MiB: the part below is hung at both ends, the part
        // above only at its low end; and the budget is spent.
        zones.hang(8 * MIB + MIB / 2, 512, true, len, 512, MIB, None);
        assert_eq!(zones.list().len(), 1);
        assert_eq!(zones.list()[0].spent, 2);
        assert!(zones.stretches(512).is_empty());
        zones.start_phase(Phase::Trimming);
        let mid = 8 * MIB + 4096 + (MIB / 2 - 4096) / 2 / 512 * 512;
        assert_eq!(
            zones.stretches(512),
            [
                Stretch {
                    from: mid,
                    to: 8 * MIB + MIB / 2,
                    down: false
                },
                Stretch {
                    from: 8 * MIB + 4096,
                    to: mid,
                    down: true
                },
                Stretch {
                    from: 8 * MIB + MIB / 2 + 512,
                    to: 9 * MIB,
                    down: true
                },
                Stretch {
                    from: 8 * MIB,
                    to: 8 * MIB + 4096,
                    down: false
                },
                Stretch {
                    from: 8 * MIB + MIB / 2,
                    to: 8 * MIB + MIB / 2 + 512,
                    down: false
                },
            ]
        );
    }

    /// The guard (round 9): a part hung at both ends is first read at its middle, never at
    /// a hang's edge; one too short to have a middle apart from both hangs gets no stretch.
    /// The upward stretch began at the low hang's edge whenever the middle rounded down to it.
    #[test]
    fn a_part_hung_at_both_ends_is_never_read_next_to_a_hang() {
        for gap in [512u64, 1024, 1536, 4096, 4608] {
            let mut zones = Zones::default();
            zones.start_phase(Phase::Copying);
            zones.seed(MIB, 2 * MIB, (MIB, MIB + 512));
            zones.seed(MIB, 2 * MIB, (MIB + 512 + gap, MIB + 1024 + gap));
            assert_eq!(zones.list().len(), 1);
            let low = MIB + 512;
            let high = low + gap;
            let inner: Vec<Stretch> = zones
                .stretches(512)
                .into_iter()
                .filter(|s| low <= s.from && s.to <= high)
                .collect();
            if gap < 1024 {
                assert!(inner.is_empty(), "gap {gap}: {inner:?}");
                continue;
            }
            let first = inner[0];
            let read = if first.down {
                first.to - 512
            } else {
                first.from
            };
            // Two sectors between hangs each touch one; from three on the middle touches none.
            assert!(
                low < read && (gap < 1536 || read + 512 < high),
                "gap {gap}: first read at {read} touches a hang: {inner:?}"
            );
        }
    }
}
