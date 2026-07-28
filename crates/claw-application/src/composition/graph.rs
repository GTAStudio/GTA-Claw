//! Ordering the composition: a deterministic plan derived from declared dependencies.

use std::collections::BTreeSet;

use super::error::CompositionError;
use super::id::SubsystemId;
use super::subsystem::{SubsystemDescriptor, SubsystemKind};

/// The order in which a set of subsystems is started, quiesced and stopped.
///
/// The plan is computed once, before anything is initialized, so a miswired
/// composition fails immediately and identically on every machine rather than
/// at the moment the broken edge is first traversed.
///
/// Ordering is a topological sort of the dependency edges, with ties broken by
/// declaration order. Two runs over the same descriptors therefore always
/// produce the same sequence, which matters because startup ordering is part of
/// what the integration tests assert.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositionPlan {
    start_order: Vec<SubsystemId>,
    ingress: Vec<SubsystemId>,
}

impl CompositionPlan {
    /// Builds a plan from the descriptors of every subsystem in the composition.
    ///
    /// # Errors
    ///
    /// - [`CompositionError::DuplicateSubsystem`] when an identifier repeats.
    /// - [`CompositionError::SelfDependency`] when a subsystem lists itself.
    /// - [`CompositionError::UnknownDependency`] when an edge points outside the
    ///   composition.
    /// - [`CompositionError::DependencyCycle`] when the edges cannot be ordered,
    ///   carrying the concrete cycle rather than just reporting that one exists.
    pub fn build(descriptors: &[SubsystemDescriptor]) -> Result<Self, CompositionError> {
        let ids: Vec<&SubsystemId> = descriptors.iter().map(SubsystemDescriptor::id).collect();

        let mut seen = BTreeSet::new();
        for id in &ids {
            if !seen.insert(*id) {
                return Err(CompositionError::DuplicateSubsystem((*id).clone()));
            }
        }

        let index_of = |wanted: &SubsystemId| ids.iter().position(|id| *id == wanted);

        let mut dependencies: Vec<Vec<usize>> = Vec::with_capacity(descriptors.len());
        for descriptor in descriptors {
            let mut edges = Vec::with_capacity(descriptor.dependencies().len());

            for dependency in descriptor.dependencies() {
                if dependency == descriptor.id() {
                    return Err(CompositionError::SelfDependency(dependency.clone()));
                }

                let target =
                    index_of(dependency).ok_or_else(|| CompositionError::UnknownDependency {
                        subsystem: descriptor.id().clone(),
                        dependency: dependency.clone(),
                    })?;

                if !edges.contains(&target) {
                    edges.push(target);
                }
            }

            dependencies.push(edges);
        }

        let order = topological_order(&dependencies).map_err(|cycle| {
            CompositionError::DependencyCycle(
                cycle
                    .into_iter()
                    .map(|position| ids[position].clone())
                    .collect(),
            )
        })?;

        let start_order: Vec<SubsystemId> = order
            .iter()
            .map(|position| ids[*position].clone())
            .collect();
        let ingress = order
            .iter()
            .filter(|position| descriptors[**position].kind() == SubsystemKind::Ingress)
            .map(|position| ids[*position].clone())
            .collect();

        Ok(Self {
            start_order,
            ingress,
        })
    }

    /// Returns the order in which subsystems are initialized and started.
    ///
    /// Every subsystem appears after all of its dependencies.
    #[must_use]
    pub fn start_order(&self) -> &[SubsystemId] {
        &self.start_order
    }

    /// Returns the order in which subsystems are shut down.
    ///
    /// This is the exact reverse of [`Self::start_order`], so a subsystem is
    /// always torn down before anything it depends on.
    #[must_use]
    pub fn shutdown_order(&self) -> Vec<SubsystemId> {
        self.start_order.iter().rev().cloned().collect()
    }

    /// Returns the order in which ingress subsystems are quiesced.
    ///
    /// Quiescing runs before draining: the daemon stops accepting new work at
    /// its edges first, then lets work already in flight finish. Ingress is
    /// listed in reverse start order for the same reason shutdown is.
    #[must_use]
    pub fn quiesce_order(&self) -> Vec<SubsystemId> {
        self.ingress.iter().rev().cloned().collect()
    }

    /// Returns how many subsystems the plan covers.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.start_order.len()
    }

    /// Returns whether the composition is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start_order.is_empty()
    }
}

/// Kahn's algorithm with the ready set held in ascending declaration order, so
/// the result is the unique smallest topological order under that tie-break.
///
/// A failure returns the cycle responsible rather than a bare `None`, so the
/// order and the explanation for its absence come out of one call. A caller
/// cannot forget to look for the cycle, and there is no second traversal that
/// could disagree with this one about whether the graph is orderable.
fn topological_order(dependencies: &[Vec<usize>]) -> Result<Vec<usize>, Vec<usize>> {
    let count = dependencies.len();
    let mut outstanding: Vec<usize> = dependencies.iter().map(Vec::len).collect();
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); count];

    for (node, edges) in dependencies.iter().enumerate() {
        for &dependency in edges {
            dependents[dependency].push(node);
        }
    }

    let mut ready: BTreeSet<usize> = (0..count).filter(|node| outstanding[*node] == 0).collect();
    let mut order = Vec::with_capacity(count);

    while let Some(&node) = ready.iter().next() {
        ready.remove(&node);
        order.push(node);

        for &dependent in &dependents[node] {
            outstanding[dependent] -= 1;
            if outstanding[dependent] == 0 {
                ready.insert(dependent);
            }
        }
    }

    if order.len() == count {
        return Ok(order);
    }

    // Kahn's stalls only on a cycle, so the search always finds one. The
    // fallback keeps that reasoning off a panic path: the nodes that could not
    // be ordered are exactly the ones the cycle runs through, so an unorderable
    // composition is still reported as unorderable and still names the
    // subsystems at fault.
    Err(find_cycle(dependencies)
        .unwrap_or_else(|| (0..count).filter(|node| outstanding[*node] > 0).collect()))
}

/// Depth-first search that returns the first cycle reachable from the lowest
/// numbered unvisited node, following dependency edges in declaration order.
fn find_cycle(dependencies: &[Vec<usize>]) -> Option<Vec<usize>> {
    const UNVISITED: u8 = 0;
    const ON_PATH: u8 = 1;
    const DONE: u8 = 2;

    let mut colour = vec![UNVISITED; dependencies.len()];

    for start in 0..dependencies.len() {
        if colour[start] != UNVISITED {
            continue;
        }

        colour[start] = ON_PATH;
        let mut path = vec![start];
        let mut stack = vec![(start, 0_usize)];

        while let Some(top) = stack.len().checked_sub(1) {
            let (node, cursor) = stack[top];

            if cursor == dependencies[node].len() {
                colour[node] = DONE;
                path.pop();
                stack.pop();
                continue;
            }

            stack[top].1 += 1;
            let next = dependencies[node][cursor];

            match colour[next] {
                UNVISITED => {
                    colour[next] = ON_PATH;
                    path.push(next);
                    stack.push((next, 0));
                }
                ON_PATH => {
                    let entry = path
                        .iter()
                        .position(|visited| *visited == next)
                        .expect("a node coloured on-path is on the path");
                    return Some(path[entry..].to_vec());
                }
                _ => {}
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::CompositionPlan;
    use crate::composition::error::CompositionError;
    use crate::composition::id::SubsystemId;
    use crate::composition::subsystem::{SubsystemDescriptor, SubsystemKind};

    fn id(value: &str) -> SubsystemId {
        SubsystemId::new(value).expect("valid subsystem id")
    }

    fn node(name: &str, dependencies: &[&str]) -> SubsystemDescriptor {
        let mut descriptor = SubsystemDescriptor::new(id(name), SubsystemKind::Capability);

        for dependency in dependencies {
            descriptor = descriptor.depends_on(id(dependency));
        }

        descriptor
    }

    fn ingress(name: &str, dependencies: &[&str]) -> SubsystemDescriptor {
        let mut descriptor = SubsystemDescriptor::new(id(name), SubsystemKind::Ingress);

        for dependency in dependencies {
            descriptor = descriptor.depends_on(id(dependency));
        }

        descriptor
    }

    fn names(ids: &[SubsystemId]) -> Vec<&str> {
        ids.iter().map(SubsystemId::as_str).collect()
    }

    #[test]
    fn dependencies_start_before_the_subsystems_that_need_them() {
        let plan = CompositionPlan::build(&[
            node("gateway", &["engine"]),
            node("engine", &["providers", "tools"]),
            node("providers", &["secrets"]),
            node("tools", &[]),
            node("secrets", &[]),
        ])
        .expect("plan builds");

        assert_eq!(
            names(plan.start_order()),
            vec!["tools", "secrets", "providers", "engine", "gateway"]
        );
    }

    #[test]
    fn independent_subsystems_keep_their_declaration_order() {
        let plan = CompositionPlan::build(&[
            node("config", &[]),
            node("observability", &[]),
            node("persistence", &[]),
        ])
        .expect("plan builds");

        assert_eq!(
            names(plan.start_order()),
            vec!["config", "observability", "persistence"]
        );

        let reversed = CompositionPlan::build(&[
            node("persistence", &[]),
            node("observability", &[]),
            node("config", &[]),
        ])
        .expect("plan builds");

        assert_eq!(
            names(reversed.start_order()),
            vec!["persistence", "observability", "config"]
        );
    }

    #[test]
    fn a_diamond_resolves_to_one_deterministic_sequence() {
        let descriptors = [
            node("top", &["left", "right"]),
            node("left", &["base"]),
            node("right", &["base"]),
            node("base", &[]),
        ];

        let first = CompositionPlan::build(&descriptors).expect("plan builds");
        let second = CompositionPlan::build(&descriptors).expect("plan builds");

        assert_eq!(
            names(first.start_order()),
            vec!["base", "left", "right", "top"]
        );
        assert_eq!(first, second);
    }

    #[test]
    fn shutdown_is_the_exact_reverse_of_startup() {
        let plan = CompositionPlan::build(&[
            node("gateway", &["engine"]),
            node("engine", &["tools"]),
            node("tools", &[]),
        ])
        .expect("plan builds");

        let mut reversed = plan.start_order().to_vec();
        reversed.reverse();

        assert_eq!(plan.shutdown_order(), reversed);
        assert_eq!(
            names(&plan.shutdown_order()),
            vec!["gateway", "engine", "tools"]
        );
        assert_eq!(plan.len(), 3);
        assert!(!plan.is_empty());
    }

    #[test]
    fn only_ingress_subsystems_are_quiesced_and_in_reverse_start_order() {
        let plan = CompositionPlan::build(&[
            node("engine", &[]),
            ingress("gateway", &["engine"]),
            ingress("http-api", &["engine"]),
            node("tools", &[]),
        ])
        .expect("plan builds");

        assert_eq!(
            names(plan.start_order()),
            vec!["engine", "gateway", "http-api", "tools"]
        );
        assert_eq!(names(&plan.quiesce_order()), vec!["http-api", "gateway"]);
    }

    #[test]
    fn an_empty_composition_produces_an_empty_plan() {
        let plan = CompositionPlan::build(&[]).expect("plan builds");

        assert!(plan.is_empty());
        assert_eq!(plan.len(), 0);
        assert!(plan.shutdown_order().is_empty());
        assert!(plan.quiesce_order().is_empty());
    }

    #[test]
    fn a_repeated_identifier_is_rejected_before_anything_is_ordered() {
        let error = CompositionPlan::build(&[node("engine", &[]), node("engine", &[])])
            .expect_err("duplicates are rejected");

        assert_eq!(error, CompositionError::DuplicateSubsystem(id("engine")));
    }

    #[test]
    fn an_edge_pointing_outside_the_composition_names_both_ends() {
        let error = CompositionPlan::build(&[node("gateway", &["engine"])])
            .expect_err("dangling edges are rejected");

        assert_eq!(
            error,
            CompositionError::UnknownDependency {
                subsystem: id("gateway"),
                dependency: id("engine"),
            }
        );
    }

    #[test]
    fn a_self_edge_is_rejected_as_such_rather_than_as_a_cycle() {
        let error = CompositionPlan::build(&[node("engine", &["engine"])])
            .expect_err("self edges are rejected");

        assert_eq!(error, CompositionError::SelfDependency(id("engine")));
    }

    #[test]
    fn a_cycle_is_reported_as_the_path_that_closes_it() {
        let error = CompositionPlan::build(&[
            node("gateway", &["engine"]),
            node("engine", &["tools"]),
            node("tools", &["gateway"]),
        ])
        .expect_err("cycles are rejected");

        assert_eq!(
            error,
            CompositionError::DependencyCycle(vec![id("gateway"), id("engine"), id("tools")])
        );
    }

    #[test]
    fn a_cycle_is_reported_even_when_acyclic_subsystems_could_still_be_ordered() {
        let error = CompositionPlan::build(&[
            node("config", &[]),
            node("left", &["right"]),
            node("right", &["left"]),
        ])
        .expect_err("cycles are rejected");

        assert_eq!(
            error,
            CompositionError::DependencyCycle(vec![id("left"), id("right")])
        );
    }

    #[test]
    fn a_two_node_cycle_reachable_only_through_an_acyclic_prefix_is_still_found() {
        let error = CompositionPlan::build(&[
            node("entry", &["left"]),
            node("left", &["right"]),
            node("right", &["left"]),
        ])
        .expect_err("cycles are rejected");

        assert_eq!(
            error,
            CompositionError::DependencyCycle(vec![id("left"), id("right")])
        );
    }

    #[test]
    fn a_repeated_dependency_edge_is_collapsed_rather_than_double_counted() {
        let mut descriptor = SubsystemDescriptor::new(id("engine"), SubsystemKind::Capability);
        descriptor = descriptor.depends_on(id("tools"));
        descriptor = descriptor.depends_on(id("tools"));

        let plan = CompositionPlan::build(&[descriptor, node("tools", &[])])
            .expect("a duplicated edge is not a defect");

        assert_eq!(names(plan.start_order()), vec!["tools", "engine"]);
    }
}
