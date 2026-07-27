//! Long-lived Slint list models for the product surfaces.
//!
//! Every repeated list is backed by a [`VecModel`] that is handed to the window
//! exactly once. Refreshes then edit the rows that actually changed instead of
//! publishing a replacement model, because `VecModel::set_vec`, `clear`, and
//! assigning a new `ModelRc` to a property all emit a model *reset*: the
//! repeater drops every instantiated row, rebuilds it, and relayouts the whole
//! list. `set_row_data`, `remove`, and `extend` only invalidate what they touch,
//! and `extend` batches an arbitrary append into a single `row_added`.

use std::rc::Rc;

use slint::{Model, VecModel};

use crate::generated_ui::{
    ActivityItem, AppWindow, DeliverableItem, DiffItem, ExtensionItem, FileItem, RunItem,
    ScheduleItem, TranscriptItem, WorkspaceItem,
};

/// Brings `model` in line with `rows` using the narrowest notifications that
/// describe the difference.
///
/// Rows that compare equal are left untouched, so a repeater only re-renders
/// what moved. Surplus rows are removed back to front, and a longer tail is
/// appended as one batched `row_added`.
pub(crate) fn reconcile<T>(model: &VecModel<T>, rows: impl IntoIterator<Item = T>)
where
    T: Clone + PartialEq + 'static,
{
    let existing = model.row_count();
    let mut applied = 0;
    let mut appended = Vec::new();
    for row in rows {
        if applied < existing {
            if model.row_data(applied).as_ref() != Some(&row) {
                model.set_row_data(applied, row);
            }
        } else {
            appended.push(row);
        }
        applied += 1;
    }
    for surplus in (applied..existing).rev() {
        model.remove(surplus);
    }
    if !appended.is_empty() {
        model.extend(appended);
    }
}

/// The set of list models the product screens repeat over.
pub(crate) struct ProductModels {
    runs: Rc<VecModel<RunItem>>,
    workspaces: Rc<VecModel<WorkspaceItem>>,
    schedules: Rc<VecModel<ScheduleItem>>,
    deliverables: Rc<VecModel<DeliverableItem>>,
    extensions: Rc<VecModel<ExtensionItem>>,
    transcript: Rc<VecModel<TranscriptItem>>,
    activity: Rc<VecModel<ActivityItem>>,
    session_files: Rc<VecModel<FileItem>>,
    diff_lines: Rc<VecModel<DiffItem>>,
}

impl ProductModels {
    /// Creates the models and binds each one to its window property once, so no
    /// later refresh has to replace a `ModelRc`.
    pub(crate) fn attach(window: &AppWindow) -> Self {
        let models = Self {
            runs: Rc::new(VecModel::default()),
            workspaces: Rc::new(VecModel::default()),
            schedules: Rc::new(VecModel::default()),
            deliverables: Rc::new(VecModel::default()),
            extensions: Rc::new(VecModel::default()),
            transcript: Rc::new(VecModel::default()),
            activity: Rc::new(VecModel::default()),
            session_files: Rc::new(VecModel::default()),
            diff_lines: Rc::new(VecModel::default()),
        };
        window.set_runs(Rc::clone(&models.runs).into());
        window.set_workspaces(Rc::clone(&models.workspaces).into());
        window.set_schedules(Rc::clone(&models.schedules).into());
        window.set_deliverables(Rc::clone(&models.deliverables).into());
        window.set_extensions(Rc::clone(&models.extensions).into());
        window.set_transcript(Rc::clone(&models.transcript).into());
        window.set_activity(Rc::clone(&models.activity).into());
        window.set_session_files(Rc::clone(&models.session_files).into());
        window.set_diff_lines(Rc::clone(&models.diff_lines).into());
        models
    }

    pub(crate) fn runs(&self) -> &VecModel<RunItem> {
        &self.runs
    }

    pub(crate) fn workspaces(&self) -> &VecModel<WorkspaceItem> {
        &self.workspaces
    }

    pub(crate) fn schedules(&self) -> &VecModel<ScheduleItem> {
        &self.schedules
    }

    pub(crate) fn deliverables(&self) -> &VecModel<DeliverableItem> {
        &self.deliverables
    }

    pub(crate) fn extensions(&self) -> &VecModel<ExtensionItem> {
        &self.extensions
    }

    pub(crate) fn transcript(&self) -> &VecModel<TranscriptItem> {
        &self.transcript
    }

    pub(crate) fn activity(&self) -> &VecModel<ActivityItem> {
        &self.activity
    }

    pub(crate) fn session_files(&self) -> &VecModel<FileItem> {
        &self.session_files
    }

    pub(crate) fn diff_lines(&self) -> &VecModel<DiffItem> {
        &self.diff_lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `Rc` compares by value but clones by pointer, so pointer identity reveals
    // whether `reconcile` rewrote a row or left the existing one in place.
    fn rows(model: &VecModel<Rc<i32>>) -> Vec<i32> {
        model.iter().map(|row| *row).collect()
    }

    #[test]
    fn reconcile_rewrites_only_the_rows_that_differ() {
        let untouched = Rc::new(1);
        let model = VecModel::from(vec![Rc::clone(&untouched), Rc::new(2), Rc::new(3)]);

        reconcile(&model, [Rc::new(1), Rc::new(9), Rc::new(3)]);

        assert_eq!(rows(&model), vec![1, 9, 3]);
        assert!(Rc::ptr_eq(
            &model.row_data(0).expect("first row survives"),
            &untouched
        ));
    }

    #[test]
    fn reconcile_appends_without_disturbing_the_existing_prefix() {
        let untouched = Rc::new(1);
        let model = VecModel::from(vec![Rc::clone(&untouched)]);

        reconcile(&model, [Rc::new(1), Rc::new(2), Rc::new(3)]);

        assert_eq!(rows(&model), vec![1, 2, 3]);
        assert!(Rc::ptr_eq(
            &model.row_data(0).expect("first row survives"),
            &untouched
        ));
    }

    #[test]
    fn reconcile_trims_surplus_rows_and_keeps_the_survivors() {
        let untouched = Rc::new(1);
        let model = VecModel::from(vec![
            Rc::clone(&untouched),
            Rc::new(2),
            Rc::new(3),
            Rc::new(4),
        ]);

        reconcile(&model, [Rc::new(1), Rc::new(2)]);

        assert_eq!(rows(&model), vec![1, 2]);
        assert!(Rc::ptr_eq(
            &model.row_data(0).expect("first row survives"),
            &untouched
        ));
    }

    #[test]
    fn reconcile_replaces_a_shorter_model_with_a_longer_changed_one() {
        let model = VecModel::from(vec![Rc::new(1), Rc::new(2)]);

        reconcile(&model, [Rc::new(7), Rc::new(8), Rc::new(9)]);

        assert_eq!(rows(&model), vec![7, 8, 9]);
    }

    #[test]
    fn reconcile_empties_a_model_without_leaving_stale_rows() {
        let model = VecModel::from(vec![Rc::new(1), Rc::new(2)]);

        reconcile(&model, []);

        assert_eq!(model.row_count(), 0);
    }
}
