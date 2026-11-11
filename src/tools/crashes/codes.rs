//! Common stop codes, their names and one plain sentence each. Codes and names are checked
//! against Microsoft's Bug Check Code Reference and Kernel Live Dump Code Reference:
//! https://learn.microsoft.com/windows-hardware/drivers/debugger/bug-check-code-reference2
//! https://learn.microsoft.com/windows-hardware/drivers/debugger/kernel-live-dump-code-reference
//!
//! The code-address parameter of each code comes from that code's own page under
//! https://learn.microsoft.com/windows-hardware/drivers/debugger/ : bug-check-0xa (p4, the
//! instruction pointer), 0x1e, 0x3b, 0x7e, 0x8e (p2, where the exception occurred), 0x50 (p3),
//! 0xd1 (p4), 0x116, 0x117, 0x141 (p2, a pointer into the responsible driver), and
//! 0x1000007e and 0x1000008e (the same parameters as 0x7e and 0x8e).

pub struct StopCode {
    pub code: u32,
    pub name: &'static str,
    pub meaning: &'static str,
    /// The parameter (1 to 4) that holds the address of the code that failed, where
    /// Microsoft's page for the code documents one.
    pub code_address: Option<usize>,
}

const fn stop(
    code: u32,
    name: &'static str,
    meaning: &'static str,
    code_address: Option<usize>,
) -> StopCode {
    StopCode {
        code,
        name,
        meaning,
        code_address,
    }
}

pub const CODES: &[StopCode] = &[
    stop(0x0A, "IRQL_NOT_LESS_OR_EQUAL", "Kernel code touched memory it may not touch at that moment, usually a driver using a bad address.", Some(4)),
    stop(0x19, "BAD_POOL_HEADER", "A block of kernel memory was found damaged, usually by a driver writing past its own memory.", None),
    stop(0x1A, "MEMORY_MANAGEMENT", "Windows found its memory bookkeeping damaged; failing RAM or a faulty driver are the usual causes.", None),
    stop(0x1E, "KMODE_EXCEPTION_NOT_HANDLED", "Kernel code hit an error nothing caught, usually in a driver.", Some(2)),
    stop(0x24, "NTFS_FILE_SYSTEM", "The NTFS file system driver failed, often from disk damage or a failing drive.", None),
    stop(0x3B, "SYSTEM_SERVICE_EXCEPTION", "Kernel code failed while serving a program's request, usually in a driver.", Some(2)),
    stop(0x4A, "IRQL_GT_ZERO_AT_SYSTEM_SERVICE", "A driver returned to a program while still at a raised interrupt level.", None),
    stop(0x4E, "PFN_LIST_CORRUPT", "The list Windows keeps of physical memory pages was damaged; failing RAM or a driver are the usual causes.", None),
    stop(0x50, "PAGE_FAULT_IN_NONPAGED_AREA", "Kernel code read or wrote memory that does not exist, from a bad driver, failing RAM or disk damage.", Some(3)),
    stop(0x77, "KERNEL_STACK_INPAGE_ERROR", "Windows could not read kernel data back from the page file, usually a disk or cable fault.", None),
    stop(0x7A, "KERNEL_DATA_INPAGE_ERROR", "Windows could not read kernel data back from disk, usually a failing drive, cable or RAM.", None),
    stop(0x7B, "INACCESSIBLE_BOOT_DEVICE", "Windows lost access to the drive it starts from, often after a storage driver or controller mode change.", None),
    stop(0x7E, "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "A system thread hit an error nothing caught, usually in a driver.", Some(2)),
    stop(0x7F, "UNEXPECTED_KERNEL_MODE_TRAP", "The processor raised a trap the kernel could not handle, from hardware faults or a kernel stack overflow.", None),
    stop(0x8E, "KERNEL_MODE_EXCEPTION_NOT_HANDLED", "Kernel code hit an error nothing caught, usually in a driver.", Some(2)),
    stop(0x9F, "DRIVER_POWER_STATE_FAILURE", "A driver did not finish a power change (sleep, wake or shutdown) in time.", None),
    stop(0xBE, "ATTEMPTED_WRITE_TO_READONLY_MEMORY", "A driver tried to write to read-only kernel memory.", None),
    stop(0xC2, "BAD_POOL_CALLER", "A driver asked for or freed kernel memory in a way that is not allowed.", None),
    stop(0xC4, "DRIVER_VERIFIER_DETECTED_VIOLATION", "Driver Verifier caught a driver breaking a rule; Driver Verifier is switched on for some drivers.", None),
    stop(0xD1, "DRIVER_IRQL_NOT_LESS_OR_EQUAL", "A driver touched memory it may not touch at that moment, usually a bad address in that driver.", Some(4)),
    stop(0xEF, "CRITICAL_PROCESS_DIED", "A process Windows cannot run without stopped, from system file damage, disk faults or security software.", None),
    stop(0xF4, "CRITICAL_OBJECT_TERMINATION", "A process or thread Windows needs ended unexpectedly, often from a failing system drive.", None),
    stop(0x101, "CLOCK_WATCHDOG_TIMEOUT", "One processor core stopped answering the others, usually unstable CPU settings, overclocking or firmware.", None),
    stop(0x109, "CRITICAL_STRUCTURE_CORRUPTION", "Windows found core kernel code or data changed, from a faulty driver, failing RAM or tampering.", None),
    stop(0x116, "VIDEO_TDR_FAILURE", "The graphics driver stopped responding and could not be reset.", Some(2)),
    stop(0x117, "VIDEO_TDR_TIMEOUT_DETECTED", "The graphics driver stopped responding and was reset; Windows carried on (a live report, not a restart).", Some(2)),
    stop(0x119, "VIDEO_SCHEDULER_INTERNAL_ERROR", "The graphics scheduler found a fatal fault, usually the graphics driver or card.", None),
    stop(0x124, "WHEA_UNCORRECTABLE_ERROR", "The hardware reported an error it could not correct: processor, memory, PCIe device, overclocking or power.", None),
    stop(0x133, "DPC_WATCHDOG_VIOLATION", "A driver held a processor at high priority for too long, often storage or network drivers or firmware.", None),
    stop(0x139, "KERNEL_SECURITY_CHECK_FAILURE", "Kernel code found its own data structures damaged, usually by a driver.", None),
    stop(0x141, "VIDEO_ENGINE_TIMEOUT_DETECTED", "A graphics engine stopped responding and was reset; Windows carried on (a live report, not a restart).", Some(2)),
    stop(0x144, "BUGCODE_USB3_DRIVER", "The USB 3 driver stack found a fault with a USB device or controller.", None),
    stop(0x154, "UNEXPECTED_STORE_EXCEPTION", "The memory compression store hit an error, often a failing drive or RAM.", None),
    stop(0x1000007E, "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M", "A system thread hit an error nothing caught, usually in a driver.", Some(2)),
    stop(0x1000008E, "KERNEL_MODE_EXCEPTION_NOT_HANDLED_M", "Kernel code hit an error nothing caught, usually in a driver.", Some(2)),
];

pub fn find(code: u32) -> Option<&'static StopCode> {
    CODES.iter().find(|entry| entry.code == code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_and_described() {
        let mut seen = std::collections::HashSet::new();
        for entry in CODES {
            assert!(seen.insert(entry.code), "{:#x} twice", entry.code);
            assert!(entry.meaning.ends_with('.'), "{}", entry.name);
            assert!(entry.code_address.is_none_or(|p| (1..=4).contains(&p)));
        }
        assert!(CODES.len() >= 30);
        assert_eq!(find(0x9F).unwrap().name, "DRIVER_POWER_STATE_FAILURE");
        assert_eq!(find(0x139).unwrap().code_address, None);
        assert_eq!(find(0x50).unwrap().code_address, Some(3));
        assert!(find(0xDEAD_BEEF).is_none());
    }
}
