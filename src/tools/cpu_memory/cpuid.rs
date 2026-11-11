//! CPUID: the processor's vendor, brand string, signature, instruction sets and cache leaves.
//! Every decoder takes register values, so the tests feed recorded leaves; `Live` asks the
//! processor the thread runs on.
use serde::{Deserialize, Serialize};

/// One CPUID answer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Regs {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// Where CPUID answers come from: the processor, or a recorded table in tests.
pub trait Source {
    fn query(&self, leaf: u32, subleaf: u32) -> Regs;
}

/// The CPUID instruction on the processor the calling thread runs on.
pub struct Live;

impl Source for Live {
    #[allow(unused_unsafe)]
    fn query(&self, leaf: u32, subleaf: u32) -> Regs {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: CPUID exists on every x86-64 processor and only reads.
            let r = unsafe { core::arch::x86_64::__cpuid_count(leaf, subleaf) };
            Regs {
                eax: r.eax,
                ebx: r.ebx,
                ecx: r.ecx,
                edx: r.edx,
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (leaf, subleaf);
            Regs::default()
        }
    }
}

/// The family, model and stepping, as read and as combined into the display values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
    pub base_family: u32,
    pub base_model: u32,
    pub extended_family: u32,
    pub extended_model: u32,
}

/// Leaf 1 EAX to the signature. The extended family counts only when the base family is
/// 0Fh; the extended model counts when the base family is 06h or 0Fh (Intel SDM Vol. 2A,
/// CPUID, "Display Family and Display Model"; AMD APM Vol. 3, CPUID Fn0000_0001_EAX).
pub fn signature(eax: u32) -> Signature {
    let stepping = eax & 0xF;
    let base_model = (eax >> 4) & 0xF;
    let base_family = (eax >> 8) & 0xF;
    let extended_model = (eax >> 16) & 0xF;
    let extended_family = (eax >> 20) & 0xFF;
    let family = if base_family == 0xF {
        base_family + extended_family
    } else {
        base_family
    };
    let model = if base_family == 0x6 || base_family == 0xF {
        (extended_model << 4) | base_model
    } else {
        base_model
    };
    Signature {
        family,
        model,
        stepping,
        base_family,
        base_model,
        extended_family,
        extended_model,
    }
}

/// Twelve bytes of register text, as CPUID gives the vendor: EBX, EDX, ECX.
fn register_text(parts: &[u32]) -> String {
    let bytes: Vec<u8> = parts.iter().flat_map(|r| r.to_le_bytes()).collect();
    clean_text(&bytes)
}

/// Printable ASCII with runs of spaces folded and the ends trimmed; NULs end the text.
pub(crate) fn clean_text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let text: String = bytes[..end]
        .iter()
        .map(|b| {
            if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                ' '
            }
        })
        .collect();
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A named group of instruction sets the processor reports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureGroup {
    pub group: String,
    pub names: Vec<String>,
}

/// A cache as one core's CPUID leaf 4 (Intel) or 8000001Dh (AMD) describes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuidCache {
    pub level: u32,
    /// "data", "instruction" or "unified".
    pub kind: String,
    pub size_bytes: u64,
    pub ways: u32,
    pub fully_associative: bool,
    pub line_bytes: u32,
    pub sets: u32,
    /// The most logical processors that may share it, as the leaf states.
    pub shared_by_at_most: u32,
}

/// Everything read through CPUID.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Cpuid {
    pub vendor: String,
    pub brand: String,
    pub signature: Signature,
    pub features: Vec<FeatureGroup>,
    /// Leaf 7 EDX bit 15: the processor mixes core types.
    pub hybrid: bool,
    /// Leaf 1 ECX bit 31: Windows runs under a hypervisor (its own, when Hyper-V or
    /// virtualization-based security is on), which may hide the processor's own features.
    pub hypervisor: bool,
    pub caches: Vec<CpuidCache>,
    /// Leaf 16h (Intel): base and maximum frequency in MHz, when given.
    pub base_mhz: Option<u32>,
    pub max_mhz: Option<u32>,
}

fn bit(value: u32, n: u32) -> bool {
    value >> n & 1 == 1
}

/// The instruction sets from leaves 1, 7 (subleaves 0 and 1) and 80000001h, grouped.
pub fn features(
    leaf1: Regs,
    leaf7: Regs,
    leaf7_1: Regs,
    ext1: Regs,
    amd: bool,
) -> Vec<FeatureGroup> {
    let pick = |list: &[(bool, &str)]| -> Vec<String> {
        list.iter()
            .filter(|(on, _)| *on)
            .map(|(_, name)| name.to_string())
            .collect()
    };
    let (c1, d1) = (leaf1.ecx, leaf1.edx);
    let (b7, c7, d7) = (leaf7.ebx, leaf7.ecx, leaf7.edx);
    let a71 = leaf7_1.eax;
    let (ce, de) = (ext1.ecx, ext1.edx);
    let groups = [
        (
            "Basic",
            pick(&[
                (bit(de, 29), "x86-64"),
                (bit(d1, 23), "MMX"),
                (bit(de, 20), "NX"),
                (bit(c1, 23), "POPCNT"),
                (bit(ce, 5), "LZCNT"),
                (bit(c1, 22), "MOVBE"),
                (bit(c1, 13), "CMPXCHG16B"),
                (bit(de, 27), "RDTSCP"),
            ]),
        ),
        (
            "SSE",
            pick(&[
                (bit(d1, 25), "SSE"),
                (bit(d1, 26), "SSE2"),
                (bit(c1, 0), "SSE3"),
                (bit(c1, 9), "SSSE3"),
                (bit(c1, 19), "SSE4.1"),
                (bit(c1, 20), "SSE4.2"),
                (amd && bit(ce, 6), "SSE4a"),
            ]),
        ),
        (
            "AVX",
            pick(&[
                (bit(c1, 28), "AVX"),
                (bit(b7, 5), "AVX2"),
                (bit(c1, 12), "FMA3"),
                (amd && bit(ce, 16), "FMA4"),
                (bit(c1, 29), "F16C"),
                (bit(a71, 4), "AVX-VNNI"),
            ]),
        ),
        (
            "AVX-512",
            pick(&[
                (bit(b7, 16), "F"),
                (bit(b7, 17), "DQ"),
                (bit(b7, 28), "CD"),
                (bit(b7, 30), "BW"),
                (bit(b7, 31), "VL"),
                (bit(b7, 21), "IFMA"),
                (bit(c7, 1), "VBMI"),
                (bit(c7, 6), "VBMI2"),
                (bit(c7, 11), "VNNI"),
                (bit(c7, 12), "BITALG"),
                (bit(c7, 14), "VPOPCNTDQ"),
                (bit(a71, 5), "BF16"),
                (bit(d7, 23), "FP16"),
                (bit(d7, 8), "VP2INTERSECT"),
            ]),
        ),
        (
            "Bit manipulation",
            pick(&[
                (bit(b7, 3), "BMI1"),
                (bit(b7, 8), "BMI2"),
                (bit(b7, 19), "ADX"),
            ]),
        ),
        (
            "Encryption and hashing",
            pick(&[
                (bit(c1, 25), "AES"),
                (bit(c1, 1), "PCLMULQDQ"),
                (bit(c7, 9), "VAES"),
                (bit(c7, 10), "VPCLMULQDQ"),
                (bit(c7, 8), "GFNI"),
                (bit(b7, 29), "SHA"),
                (bit(c1, 30), "RDRAND"),
                (bit(b7, 18), "RDSEED"),
            ]),
        ),
        (
            "Matrix",
            pick(&[
                (bit(d7, 24), "AMX-TILE"),
                (bit(d7, 22), "AMX-BF16"),
                (bit(d7, 25), "AMX-INT8"),
            ]),
        ),
        (
            "Virtualization",
            pick(&[(bit(c1, 5), "VT-x"), (amd && bit(ce, 2), "AMD-V")]),
        ),
        (
            "Security",
            pick(&[
                (bit(b7, 2), "SGX"),
                (bit(b7, 20), "SMAP"),
                (bit(b7, 7), "SMEP"),
                (bit(c7, 7), "CET shadow stack"),
            ]),
        ),
    ];
    groups
        .into_iter()
        .filter(|(_, names)| !names.is_empty())
        .map(|(group, names)| FeatureGroup {
            group: group.into(),
            names,
        })
        .collect()
}

/// Decodes one leaf 4 or 8000001Dh subleaf; None when it ends the list (type 0).
pub fn cache_leaf(r: Regs) -> Option<CpuidCache> {
    let kind = match r.eax & 0x1F {
        1 => "data",
        2 => "instruction",
        3 => "unified",
        _ => return None,
    };
    let level = (r.eax >> 5) & 0x7;
    let shared = ((r.eax >> 14) & 0xFFF) + 1;
    let fully_associative = bit(r.eax, 9);
    let line = (r.ebx & 0xFFF) + 1;
    let partitions = ((r.ebx >> 12) & 0x3FF) + 1;
    let ways = ((r.ebx >> 22) & 0x3FF) + 1;
    let sets = r.ecx.wrapping_add(1);
    let size = u64::from(ways) * u64::from(partitions) * u64::from(line) * u64::from(sets);
    Some(CpuidCache {
        level,
        kind: kind.into(),
        size_bytes: size,
        ways,
        fully_associative,
        line_bytes: line,
        sets,
        shared_by_at_most: shared,
    })
}

/// Reads everything from `source`.
pub fn read(source: &dyn Source) -> Cpuid {
    let leaf0 = source.query(0, 0);
    let max_leaf = leaf0.eax;
    let vendor = register_text(&[leaf0.ebx, leaf0.edx, leaf0.ecx]);
    let amd = vendor == "AuthenticAMD" || vendor == "HygonGenuine";
    let leaf = |n: u32, sub: u32| {
        if n <= max_leaf {
            source.query(n, sub)
        } else {
            Regs::default()
        }
    };
    let max_ext = source.query(0x8000_0000, 0).eax;
    let ext = |n: u32, sub: u32| {
        if (0x8000_0000..=max_ext).contains(&n) && max_ext < 0x8000_0100 {
            source.query(n, sub)
        } else {
            Regs::default()
        }
    };
    let leaf1 = leaf(1, 0);
    let leaf7 = leaf(7, 0);
    let leaf7_1 = if leaf7.eax >= 1 {
        leaf(7, 1)
    } else {
        Regs::default()
    };
    let ext1 = ext(0x8000_0001, 0);
    let brand_regs: Vec<u32> = (0x8000_0002..=0x8000_0004)
        .flat_map(|n| {
            let r = ext(n, 0);
            [r.eax, r.ebx, r.ecx, r.edx]
        })
        .collect();
    // Leaf 4 on Intel; on AMD 8000001Dh, present with the topology extensions (8000_0001h
    // ECX bit 22). At most 16 subleaves, whatever the processor claims.
    let caches = if amd {
        if bit(ext1.ecx, 22) {
            (0..16)
                .map_while(|sub| cache_leaf(ext(0x8000_001D, sub)))
                .collect()
        } else {
            Vec::new()
        }
    } else {
        (0..16).map_while(|sub| cache_leaf(leaf(4, sub))).collect()
    };
    let leaf16 = leaf(0x16, 0);
    let mhz = |v: u32| (v & 0xFFFF != 0).then_some(v & 0xFFFF);
    Cpuid {
        vendor,
        brand: register_text(&brand_regs),
        signature: signature(leaf1.eax),
        features: features(leaf1, leaf7, leaf7_1, ext1, amd),
        hybrid: !amd && bit(leaf7.edx, 15),
        hypervisor: bit(leaf1.ecx, 31),
        caches,
        base_mhz: mhz(leaf16.eax),
        max_mhz: mhz(leaf16.ebx),
    }
}

/// A design name for a family and model, with the table it came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Design {
    /// "codename" for Intel, "microarchitecture" for AMD, which that table names instead.
    pub kind: String,
    pub name: String,
    pub source: String,
}

/// Intel family 6 models with one codename each, from the Linux kernel's
/// arch/x86/include/asm/intel-family.h (read 2026-11-06). Models that file says several
/// codenames share by stepping (0x55, 0x8E, 0x9E) are left out.
const INTEL: &[(u32, &str)] = &[
    (0x3C, "Haswell"),
    (0x3F, "Haswell-X"),
    (0x45, "Haswell (low power)"),
    (0x46, "Haswell (with eDRAM graphics)"),
    (0x3D, "Broadwell"),
    (0x47, "Broadwell (with eDRAM graphics)"),
    (0x4F, "Broadwell-X"),
    (0x56, "Broadwell-D"),
    (0x4E, "Skylake (low power)"),
    (0x5E, "Skylake"),
    (0xA5, "Comet Lake"),
    (0xA6, "Comet Lake (low power)"),
    (0x66, "Cannon Lake (low power)"),
    (0x6A, "Ice Lake-X"),
    (0x6C, "Ice Lake-D"),
    (0x7D, "Ice Lake"),
    (0x7E, "Ice Lake (low power)"),
    (0xA7, "Rocket Lake"),
    (0x8C, "Tiger Lake (low power)"),
    (0x8D, "Tiger Lake"),
    (0x8F, "Sapphire Rapids"),
    (0xCF, "Emerald Rapids"),
    (0xAD, "Granite Rapids"),
    (0xAE, "Granite Rapids-D"),
    (0x8A, "Lakefield"),
    (0x97, "Alder Lake"),
    (0x9A, "Alder Lake (low power)"),
    (0xB7, "Raptor Lake"),
    (0xBA, "Raptor Lake-P"),
    (0xBF, "Raptor Lake-S"),
    (0xAC, "Meteor Lake"),
    (0xAA, "Meteor Lake (low power)"),
    (0xC5, "Arrow Lake-H"),
    (0xC6, "Arrow Lake"),
    (0xB5, "Arrow Lake-U"),
    (0xBD, "Lunar Lake"),
    (0xCC, "Panther Lake"),
];

/// AMD family and model ranges to Zen generations, from bsp_init_amd in the Linux kernel's
/// arch/x86/kernel/cpu/amd.c (read 2026-11-06).
const AMD: &[(u32, u32, u32, &str)] = &[
    (0x17, 0x00, 0x2F, "Zen"),
    (0x17, 0x50, 0x5F, "Zen"),
    (0x17, 0x30, 0x4F, "Zen 2"),
    (0x17, 0x60, 0x7F, "Zen 2"),
    (0x17, 0x90, 0x91, "Zen 2"),
    (0x17, 0xA0, 0xAF, "Zen 2"),
    (0x19, 0x00, 0x0F, "Zen 3"),
    (0x19, 0x20, 0x5F, "Zen 3"),
    (0x19, 0x10, 0x1F, "Zen 4"),
    (0x19, 0x60, 0xAF, "Zen 4"),
    (0x1A, 0x00, 0x2F, "Zen 5"),
    (0x1A, 0x40, 0x4F, "Zen 5"),
    (0x1A, 0x60, 0x7F, "Zen 5"),
    (0x1A, 0xD0, 0xD7, "Zen 5"),
    (0x1A, 0x50, 0x5F, "Zen 6"),
    (0x1A, 0x80, 0xAF, "Zen 6"),
    (0x1A, 0xC0, 0xCF, "Zen 6"),
    (0x1A, 0xD8, 0xEF, "Zen 6"),
];

/// The design for a vendor, family and model, only where a cited table names it.
pub fn design(vendor: &str, sig: &Signature) -> Option<Design> {
    match vendor {
        "GenuineIntel" if sig.family == 6 => INTEL
            .iter()
            .find(|(model, _)| *model == sig.model)
            .map(|(_, name)| Design {
                kind: "codename".into(),
                name: (*name).into(),
                source: "Linux kernel, arch/x86/include/asm/intel-family.h".into(),
            }),
        "AuthenticAMD" => AMD
            .iter()
            .find(|(family, low, high, _)| {
                *family == sig.family && (*low..=*high).contains(&sig.model)
            })
            .map(|(_, _, _, name)| Design {
                kind: "microarchitecture".into(),
                name: (*name).into(),
                source: "Linux kernel, arch/x86/kernel/cpu/amd.c".into(),
            }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Table(HashMap<(u32, u32), Regs>);

    impl Source for Table {
        fn query(&self, leaf: u32, subleaf: u32) -> Regs {
            self.0.get(&(leaf, subleaf)).copied().unwrap_or_default()
        }
    }

    fn text_regs(text: &str) -> Vec<u32> {
        let mut bytes = text.as_bytes().to_vec();
        bytes.resize(48, 0);
        bytes
            .chunks(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect()
    }

    /// Leaves as an AMD Ryzen 7 7800X3D answered them on one test machine, under
    /// Windows' hypervisor (family 19h model 61h stepping 2).
    fn ryzen() -> Table {
        let mut t = HashMap::new();
        let v = text_regs("AuthenticAMD");
        t.insert(
            (0, 0),
            Regs {
                eax: 0xD,
                ebx: v[0],
                edx: v[1],
                ecx: v[2],
            },
        );
        t.insert(
            (1, 0),
            Regs {
                eax: 0x00A6_0F12,
                ebx: 0x0A10_0800,
                ecx: 0xFED8_320B,
                edx: 0x178B_FBFF,
            },
        );
        t.insert(
            (7, 0),
            Regs {
                eax: 1,
                ebx: 0xF1BF_97A9,
                ecx: 0x0040_5FC6,
                edx: 0x0000_0010,
            },
        );
        t.insert(
            (7, 1),
            Regs {
                eax: 0x20,
                ..Regs::default()
            },
        );
        t.insert(
            (0x8000_0000, 0),
            Regs {
                eax: 0x8000_0027,
                ..Regs::default()
            },
        );
        t.insert(
            (0x8000_0001, 0),
            Regs {
                eax: 0x00A6_0F12,
                ebx: 0,
                ecx: 0x20C0_23F3,
                edx: 0x2FD3_FBFF,
            },
        );
        let brand = text_regs("AMD Ryzen 7 7800X3D 8-Core Processor           ");
        for (i, n) in (0x8000_0002u32..=0x8000_0004).enumerate() {
            t.insert(
                (n, 0),
                Regs {
                    eax: brand[i * 4],
                    ebx: brand[i * 4 + 1],
                    ecx: brand[i * 4 + 2],
                    edx: brand[i * 4 + 3],
                },
            );
        }
        // L1d and L1i 32 KiB 8-way, L2 1 MiB 8-way, L3 96 MiB 16-way shared by 16.
        for (sub, eax, ebx, ecx) in [
            (0, 0x0000_4121, 0x01C0_003F, 0x3F),
            (1, 0x0000_4122, 0x01C0_003F, 0x3F),
            (2, 0x0000_4143, 0x01C0_003F, 0x7FF),
            (3, 0x0003_C163, 0x03C0_003F, 0x1_7FFF),
        ] {
            t.insert(
                (0x8000_001D, sub),
                Regs {
                    eax,
                    ebx,
                    ecx,
                    edx: 0,
                },
            );
        }
        Table(t)
    }

    #[test]
    fn signatures_combine_the_extended_fields_only_where_the_manuals_say() {
        // AMD family 19h model 61h stepping 2.
        let s = signature(0x00A6_0F12);
        assert_eq!((s.family, s.model, s.stepping), (0x19, 0x61, 2));
        assert_eq!((s.base_family, s.extended_family), (0xF, 0xA));
        // Intel family 6 model 0xB7 stepping 1 (Raptor Lake).
        let s = signature(0x000B_0671);
        assert_eq!((s.family, s.model, s.stepping), (6, 0xB7, 1));
        // A base family other than 6 or 15 keeps its model and ignores both extensions.
        let s = signature(0x0FF0_0543);
        assert_eq!((s.family, s.model, s.stepping), (5, 4, 3));
    }

    #[test]
    fn a_recorded_ryzen_reads_as_itself() {
        let c = read(&ryzen());
        assert_eq!(c.vendor, "AuthenticAMD");
        assert_eq!(c.brand, "AMD Ryzen 7 7800X3D 8-Core Processor");
        assert_eq!((c.signature.family, c.signature.model), (0x19, 0x61));
        let names: Vec<&str> = c
            .features
            .iter()
            .flat_map(|g| g.names.iter().map(String::as_str))
            .collect();
        for want in [
            "x86-64", "LZCNT", "SSE4.2", "SSE4a", "AVX", "AVX2", "FMA3", "F", "VL", "BF16", "AES",
            "SHA", "BMI2",
        ] {
            assert!(names.contains(&want), "{want} missing from {names:?}");
        }
        // Windows' hypervisor hides the processor's own virtualization support.
        assert!(c.hypervisor);
        assert!(!names.contains(&"VT-x") && !names.contains(&"AMD-V"));
        assert!(!c.hybrid);
        assert_eq!(c.caches.len(), 4);
        assert_eq!(c.caches[1].kind, "instruction");
        assert_eq!(c.caches[0].size_bytes, 32 * 1024);
        assert_eq!(c.caches[2].size_bytes, 1024 * 1024);
        assert_eq!(c.caches[3].size_bytes, 96 * 1024 * 1024);
        assert_eq!(c.caches[3].ways, 16);
        assert_eq!(c.caches[3].shared_by_at_most, 16);
        assert_eq!(c.base_mhz, None);
        assert_eq!(
            design(&c.vendor, &c.signature).map(|d| d.name),
            Some("Zen 4".into())
        );
    }

    #[test]
    fn leaves_past_the_maximum_are_never_asked() {
        // A table that answers garbage for every leaf but says leaf 1 is its last.
        struct Wild;
        impl Source for Wild {
            fn query(&self, leaf: u32, _sub: u32) -> Regs {
                match leaf {
                    0 => Regs {
                        eax: 1,
                        ..Regs::default()
                    },
                    0x8000_0000 => Regs::default(),
                    _ => Regs {
                        eax: u32::MAX,
                        ebx: u32::MAX,
                        ecx: u32::MAX,
                        edx: u32::MAX,
                    },
                }
            }
        }
        let c = read(&Wild);
        assert!(c.caches.is_empty());
        assert_eq!(c.base_mhz, None);
        assert_eq!(c.brand, "");
    }

    #[test]
    fn designs_come_only_from_the_cited_tables() {
        let sig = |family, model| Signature {
            family,
            model,
            ..Signature::default()
        };
        assert_eq!(
            design("GenuineIntel", &sig(6, 0x97)).map(|d| d.name),
            Some("Alder Lake".into())
        );
        // Shared by several codenames, so none is given.
        assert_eq!(design("GenuineIntel", &sig(6, 0x9E)), None);
        assert_eq!(design("GenuineIntel", &sig(6, 0x55)), None);
        assert_eq!(
            design("AuthenticAMD", &sig(0x19, 0x21)).unwrap().name,
            "Zen 3"
        );
        assert_eq!(design("AuthenticAMD", &sig(0x19, 0xB0)), None);
        assert_eq!(design("CentaurHauls", &sig(6, 0x97)), None);
    }

    #[test]
    fn text_from_registers_is_printable_and_trimmed() {
        assert_eq!(clean_text(b"  Intel(R)\x01Core\0garbage"), "Intel(R) Core");
        assert_eq!(clean_text(b""), "");
    }
}
