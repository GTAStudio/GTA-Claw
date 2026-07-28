//! Search and selection state for the desktop command palette.

use std::collections::HashSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::generated_ui::CommandItem;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum PaletteAction {
    Focus,
    Workspaces,
    Runs,
    Schedules,
    Deliverables,
    Extensions,
    Settings,
    KeyboardShortcuts,
    Update,
    Diagnostics,
}

impl PaletteAction {
    pub(crate) const fn from_id(id: i32) -> Option<Self> {
        match id {
            0 => Some(Self::Focus),
            1 => Some(Self::Workspaces),
            2 => Some(Self::Runs),
            3 => Some(Self::Schedules),
            4 => Some(Self::Deliverables),
            5 => Some(Self::Extensions),
            6 => Some(Self::Settings),
            7 => Some(Self::KeyboardShortcuts),
            8 => Some(Self::Update),
            9 => Some(Self::Diagnostics),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
struct IndexedCommand {
    item: CommandItem,
    search_index: String,
}

#[derive(Clone, Debug)]
pub(crate) struct CommandPaletteState {
    commands: Vec<IndexedCommand>,
    query_terms: Vec<String>,
    selected_index: usize,
}

impl CommandPaletteState {
    pub(crate) fn new(
        catalog: impl IntoIterator<Item = CommandItem>,
    ) -> Result<Self, PaletteCatalogError> {
        let mut actions = HashSet::new();
        let mut commands = Vec::new();
        for item in catalog {
            let Some(action) = PaletteAction::from_id(item.action_id) else {
                return Err(PaletteCatalogError::UnknownAction(item.action_id));
            };
            if item.title.trim().is_empty() {
                return Err(PaletteCatalogError::MissingTitle(item.action_id));
            }
            if !actions.insert(action) {
                return Err(PaletteCatalogError::DuplicateAction(item.action_id));
            }
            let search_index =
                format!("{} {} {}", item.title, item.detail, item.keywords).to_lowercase();
            commands.push(IndexedCommand { item, search_index });
        }
        if commands.is_empty() {
            return Err(PaletteCatalogError::Empty);
        }
        Ok(Self {
            commands,
            query_terms: Vec::new(),
            selected_index: 0,
        })
    }

    pub(crate) fn update_query(&mut self, query: &str) -> bool {
        let terms = query
            .split_whitespace()
            .map(str::to_lowercase)
            .collect::<Vec<_>>();
        if self.query_terms == terms {
            false
        } else {
            self.query_terms = terms;
            self.selected_index = 0;
            true
        }
    }

    pub(crate) fn reset(&mut self) {
        self.query_terms.clear();
        self.selected_index = 0;
    }

    pub(crate) fn move_selection(&mut self, step: i32) {
        let count = self.visible_count();
        if count == 0 {
            self.selected_index = 0;
        } else if step > 0 {
            self.selected_index = (self.selected_index + 1) % count;
        } else if step < 0 {
            self.selected_index = self.selected_index.checked_sub(1).unwrap_or(count - 1);
        }
    }

    pub(crate) const fn selected_index(&self) -> usize {
        self.selected_index
    }

    #[cfg(test)]
    pub(crate) fn selected_action_id(&self) -> Option<i32> {
        self.visible()
            .nth(self.selected_index)
            .map(|entry| entry.item.action_id)
    }

    #[cfg(test)]
    pub(crate) fn selected_label(&self) -> Option<&str> {
        self.visible()
            .nth(self.selected_index)
            .map(|entry| entry.item.title.as_str())
    }

    pub(crate) fn visible_count(&self) -> usize {
        self.visible().count()
    }

    pub(crate) fn visible_items(&self) -> impl Iterator<Item = CommandItem> + '_ {
        self.visible().map(|entry| entry.item.clone())
    }

    fn visible(&self) -> impl Iterator<Item = &IndexedCommand> {
        self.commands.iter().filter(|command| {
            self.query_terms
                .iter()
                .all(|term| command.search_index.contains(term))
        })
    }

    #[cfg(test)]
    fn selected_action(&self) -> Option<PaletteAction> {
        self.selected_action_id().and_then(PaletteAction::from_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PaletteCatalogError {
    Empty,
    UnknownAction(i32),
    DuplicateAction(i32),
    MissingTitle(i32),
}

impl Display for PaletteCatalogError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("the command catalog is empty"),
            Self::UnknownAction(id) => write!(formatter, "command action {id} is unknown"),
            Self::DuplicateAction(id) => write!(formatter, "command action {id} is duplicated"),
            Self::MissingTitle(id) => write!(formatter, "command action {id} has no title"),
        }
    }
}

impl Error for PaletteCatalogError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(action_id: i32, title: &str, detail: &str, keywords: &str) -> CommandItem {
        CommandItem {
            action_id,
            glyph: title.chars().next().unwrap_or('?').to_string().into(),
            title: title.into(),
            detail: detail.into(),
            keywords: keywords.into(),
        }
    }

    fn catalog() -> Vec<CommandItem> {
        vec![
            command(0, "Go to Focus", "Ctrl/Cmd+1", "home attention overview"),
            command(
                1,
                "Go to Workspaces",
                "Ctrl/Cmd+2",
                "repository local remote git",
            ),
            command(8, "Check for updates", "Settings", "release upgrade"),
            command(9, "Open diagnostics", "Settings", "health renderer gateway"),
        ]
    }

    fn visible_titles(state: &CommandPaletteState) -> Vec<String> {
        state
            .visible_items()
            .map(|item| item.title.to_string())
            .collect()
    }

    #[test]
    fn search_is_case_insensitive_tokenized_and_stable() {
        let mut state = CommandPaletteState::new(catalog()).expect("valid catalog");

        assert!(state.update_query("LOCAL git"));
        assert_eq!(visible_titles(&state), vec!["Go to Workspaces"]);
        assert_eq!(state.selected_action(), Some(PaletteAction::Workspaces));
        assert!(!state.update_query(" local GIT "));

        assert!(state.update_query("health"));
        assert_eq!(visible_titles(&state), vec!["Open diagnostics"]);
        assert_eq!(state.selected_action(), Some(PaletteAction::Diagnostics));

        assert!(state.update_query("missing command"));
        assert!(visible_titles(&state).is_empty());
        assert_eq!(state.selected_action(), None);
        assert_eq!(state.selected_action_id(), None);
        assert_eq!(state.selected_label(), None);
    }

    #[test]
    fn arrow_selection_wraps_and_query_changes_select_the_first_match() {
        let mut state = CommandPaletteState::new(catalog()).expect("valid catalog");

        state.move_selection(-1);
        assert_eq!(state.selected_action(), Some(PaletteAction::Diagnostics));
        state.move_selection(1);
        assert_eq!(state.selected_action(), Some(PaletteAction::Focus));
        state.move_selection(1);
        assert_eq!(state.selected_action(), Some(PaletteAction::Workspaces));

        state.update_query("settings");
        assert_eq!(state.selected_index(), 0);
        assert_eq!(state.selected_action(), Some(PaletteAction::Update));
        state.move_selection(1);
        assert_eq!(state.selected_action(), Some(PaletteAction::Diagnostics));
        state.move_selection(1);
        assert_eq!(state.selected_action(), Some(PaletteAction::Update));

        state.reset();
        assert_eq!(visible_titles(&state).len(), 4);
        assert_eq!(state.selected_action(), Some(PaletteAction::Focus));
    }

    #[test]
    fn malformed_catalogs_are_rejected_before_the_window_runs() {
        assert_eq!(
            CommandPaletteState::new(Vec::<CommandItem>::new()).unwrap_err(),
            PaletteCatalogError::Empty
        );
        assert_eq!(
            CommandPaletteState::new([command(42, "Unknown", "", "")]).unwrap_err(),
            PaletteCatalogError::UnknownAction(42)
        );
        assert_eq!(
            CommandPaletteState::new([
                command(0, "Focus", "", ""),
                command(0, "Focus again", "", ""),
            ])
            .unwrap_err(),
            PaletteCatalogError::DuplicateAction(0)
        );
        assert_eq!(
            CommandPaletteState::new([command(0, " ", "", "")]).unwrap_err(),
            PaletteCatalogError::MissingTitle(0)
        );
    }
}
