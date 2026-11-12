#![cfg(windows)]
pub mod budget;
pub mod change_record;
pub mod checks;
pub mod clock;
pub mod event_list;
pub mod events;
pub mod expanded_probes;
pub mod handles;
pub mod inventory_view;
pub mod live;
pub mod operator_tools;
mod pdf_writer;
pub mod protocol;
pub mod recovery;
pub mod remote_policy;
pub mod report;
pub mod restore;
pub mod runner;
pub mod session;
pub mod site;
pub mod site_rules;
pub mod support_client;
pub mod support_transport;
pub mod tools;
pub mod ui_layout;
pub mod update;

pub use checks::{collect_inventory, run_catalog};

/// One repair, declared in full before a runner may carry it out. The operator and the AI decide
/// each repair; the runner records every command and change in the activity record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairPlan {
    /// Stable action id from the reviewed repair catalog, such as `windows.sfc_scan`.
    pub action: &'static str,
    /// Typed arguments by name, in the order the action declares them.
    pub arguments: Vec<(&'static str, RepairArgument)>,
    /// What the repair touches, such as one service or the Windows component store.
    pub scope: &'static str,
    pub interruption: Interruption,
    pub elevation: Elevation,
    /// How the result is checked once the repair has run.
    pub verification: &'static str,
    pub rollback: Rollback,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepairArgument {
    Flag(bool),
    Number(u64),
    Text(String),
}

/// What the person at the PC will notice while the repair runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interruption {
    None,
    Minutes(u32),
    Restart,
}

/// Administrator means Windows' own administrator prompt; nothing else elevates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Elevation {
    CurrentUser,
    Administrator,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rollback {
    /// How to undo the change.
    Undo(&'static str),
    /// Why the change cannot be undone.
    Irreversible(&'static str),
}

impl RepairPlan {
    /// Names the declarations left blank. A runner refuses a repair unless this is empty.
    pub fn undeclared(&self) -> Vec<&'static str> {
        let rollback = match self.rollback {
            Rollback::Undo(text) | Rollback::Irreversible(text) => text,
        };
        [
            ("action", self.action),
            ("scope", self.scope),
            ("verification", self.verification),
            ("rollback", rollback),
        ]
        .into_iter()
        .filter(|(_, text)| text.trim().is_empty())
        .map(|(name, _)| name)
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sfc_scan() -> RepairPlan {
        RepairPlan {
            action: "windows.sfc_scan",
            arguments: vec![("verify_only", RepairArgument::Flag(false))],
            scope: "Windows system files",
            interruption: Interruption::Minutes(15),
            elevation: Elevation::Administrator,
            verification: "sfc reports no integrity violations on a second run",
            rollback: Rollback::Irreversible("replaced files come from the component store"),
        }
    }

    #[test]
    fn a_full_declaration_has_nothing_undeclared() {
        assert!(sfc_scan().undeclared().is_empty());
    }

    #[test]
    fn blank_declarations_are_named() {
        let blank = RepairPlan {
            action: "",
            scope: " ",
            verification: "",
            rollback: Rollback::Undo(""),
            ..sfc_scan()
        };
        assert_eq!(
            blank.undeclared(),
            ["action", "scope", "verification", "rollback"]
        );
        let partial = RepairPlan {
            verification: "",
            ..sfc_scan()
        };
        assert_eq!(partial.undeclared(), ["verification"]);
    }
}
