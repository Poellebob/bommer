//! Source-level architecture checks, not a replacement for rustc name resolution.
//! Macro token bodies/expansions, include!, method dispatch, and inferred types are
//! not resolved. Non-test cfg branches are inspected conservatively, not evaluated.
//! This models module/item imports, not local variable or generic-parameter bindings.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use syn::visit::{self, Visit};

// The empty module path denotes main, the crate root.
type Name = Vec<String>;
type Edges = BTreeSet<(Name, Name)>;

#[derive(Clone, Debug)]
struct Import {
    path: Name,
    alias: Option<String>,
}

#[derive(Default)]
struct Scope {
    parent: Option<usize>,
    module: Name,
    names: BTreeSet<String>,
    imports: Vec<Import>,
}

#[derive(Default)]
struct SourceGraph {
    modules: BTreeMap<Name, usize>,
    scopes: Vec<Scope>,
    paths: Vec<(usize, Name)>,
}

fn test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if attr.path().is_ident("test") {
            return true;
        }

        if !attr.path().is_ident("cfg") {
            return false;
        }

        // Parse cfg syntax rather than looking for the word "test" in source.
        attr.parse_args::<syn::Meta>().is_ok_and(|meta| match meta {
            syn::Meta::Path(path) => path.is_ident("test"),
            syn::Meta::List(list) if list.path.is_ident("all") => {
                use syn::parse::Parser;

                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
                    .parse2(list.tokens)
                    .is_ok_and(|items| {
                        items.iter().any(
                            |item| matches!(item, syn::Meta::Path(path) if path.is_ident("test")),
                        )
                    })
            }
            _ => false,
        })
    })
}

fn imports(tree: &syn::UseTree, prefix: Name, output: &mut Vec<Import>) {
    match tree {
        syn::UseTree::Path(path) => {
            let mut prefix = prefix;
            prefix.push(path.ident.to_string());
            imports(&path.tree, prefix, output);
        }
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                imports(tree, prefix.clone(), output);
            }
        }
        syn::UseTree::Glob(_) => output.push(Import {
            path: prefix,
            alias: None,
        }),
        syn::UseTree::Name(name) => {
            let mut path = prefix;
            let alias = if name.ident == "self" {
                path.last().cloned()
            } else {
                path.push(name.ident.to_string());
                Some(name.ident.to_string())
            };

            output.push(Import { path, alias });
        }
        syn::UseTree::Rename(rename) => {
            let mut path = prefix;

            if rename.ident != "self" {
                path.push(rename.ident.to_string());
            }

            output.push(Import {
                path,
                alias: Some(rename.rename.to_string()),
            });
        }
    }
}

fn item_name(item: &syn::Item) -> Option<String> {
    let ident = match item {
        syn::Item::Const(item) => &item.ident,
        syn::Item::Enum(item) => &item.ident,
        syn::Item::Fn(item) => &item.sig.ident,
        syn::Item::Mod(item) => &item.ident,
        syn::Item::Static(item) => &item.ident,
        syn::Item::Struct(item) => &item.ident,
        syn::Item::Trait(item) => &item.ident,
        syn::Item::TraitAlias(item) => &item.ident,
        syn::Item::Type(item) => &item.ident,
        syn::Item::Union(item) => &item.ident,
        _ => return None,
    };

    Some(ident.to_string())
}

fn skipped(item: &syn::Item) -> bool {
    match item {
        syn::Item::Mod(item) => {
            item.ident == "tests"
                || item.ident.to_string().ends_with("_tests")
                || test_only(&item.attrs)
        }
        syn::Item::Fn(item) => test_only(&item.attrs),
        syn::Item::Use(item) => test_only(&item.attrs),
        syn::Item::Const(item) => test_only(&item.attrs),
        syn::Item::Enum(item) => test_only(&item.attrs),
        syn::Item::ExternCrate(item) => test_only(&item.attrs),
        syn::Item::ForeignMod(item) => test_only(&item.attrs),
        syn::Item::Impl(item) => test_only(&item.attrs),
        syn::Item::Macro(item) => test_only(&item.attrs),
        syn::Item::Static(item) => test_only(&item.attrs),
        syn::Item::Struct(item) => test_only(&item.attrs),
        syn::Item::Trait(item) => test_only(&item.attrs),
        syn::Item::TraitAlias(item) => test_only(&item.attrs),
        syn::Item::Type(item) => test_only(&item.attrs),
        syn::Item::Union(item) => test_only(&item.attrs),
        _ => false,
    }
}

impl SourceGraph {
    fn load(root: &Path, read: &impl Fn(&Path) -> Result<String, String>) -> Result<Self, String> {
        let mut graph = Self::default();
        let source = read(root)?;
        let file =
            syn::parse_file(&source).map_err(|error| format!("{}: {error}", root.display()))?;

        graph.module(Vec::new(), file.items, root.parent().unwrap(), read)?;

        Ok(graph)
    }

    fn scope(&mut self, module: Name, parent: Option<usize>, items: &[syn::Item]) -> usize {
        let mut scope = Scope {
            module,
            parent,
            ..Scope::default()
        };

        for item in items.iter().filter(|item| !skipped(item)) {
            if let Some(name) = item_name(item) {
                scope.names.insert(name);
            }

            if let syn::Item::Use(item) = item {
                let prefix = if item.leading_colon.is_some() {
                    vec!["::".to_owned()]
                } else {
                    Vec::new()
                };
                imports(&item.tree, prefix, &mut scope.imports);
            }

            if let syn::Item::ExternCrate(item) = item {
                scope.imports.push(Import {
                    path: vec!["::".to_owned(), item.ident.to_string()],
                    alias: Some(
                        item.rename
                            .as_ref()
                            .map_or(&item.ident, |(_, alias)| alias)
                            .to_string(),
                    ),
                });
            }
        }

        let index = self.scopes.len();
        self.scopes.push(scope);

        index
    }

    fn module(
        &mut self,
        name: Name,
        items: Vec<syn::Item>,
        directory: &Path,
        read: &impl Fn(&Path) -> Result<String, String>,
    ) -> Result<(), String> {
        let scope = self.scope(name.clone(), None, &items);
        self.modules.insert(name.clone(), scope);

        for item in &items {
            if skipped(item) {
                continue;
            }

            if let syn::Item::Mod(module) = item {
                let mut child = name.clone();
                child.push(module.ident.to_string());

                if let Some((_, items)) = &module.content {
                    self.module(
                        child,
                        items.clone(),
                        &directory.join(module.ident.to_string()),
                        read,
                    )?;
                } else {
                    let explicit = module.attrs.iter().find_map(|attr| {
                        if !attr.path().is_ident("path") {
                            return None;
                        }

                        match &attr.meta {
                            syn::Meta::NameValue(value) => match &value.value {
                                syn::Expr::Lit(syn::ExprLit {
                                    lit: syn::Lit::Str(path),
                                    ..
                                }) => Some(path.value()),
                                _ => None,
                            },
                            _ => None,
                        }
                    });

                    let (path, source) = if let Some(path) = explicit {
                        let path = directory.join(path);
                        let source = read(&path)?;
                        (path, source)
                    } else {
                        let flat = directory.join(format!("{}.rs", module.ident));
                        let nested = directory.join(module.ident.to_string()).join("mod.rs");

                        match (read(&flat), read(&nested)) {
                            (Ok(source), Err(_)) => (flat, source),
                            (Err(_), Ok(source)) => (nested, source),
                            (Ok(_), Ok(_)) => {
                                return Err(format!("ambiguous module: {}", module.ident));
                            }
                            (Err(error), Err(_)) => return Err(error),
                        }
                    };

                    let file = syn::parse_file(&source)
                        .map_err(|error| format!("{}: {error}", path.display()))?;
                    let directory = if path.file_name().is_some_and(|name| name == "mod.rs") {
                        path.parent().unwrap().to_path_buf()
                    } else {
                        path.with_extension("")
                    };

                    self.module(child, file.items, &directory, read)?;
                }
            } else {
                Paths { graph: self, scope }.visit_item(item);
            }
        }

        Ok(())
    }

    fn resolve(
        &self,
        scope: usize,
        path: &[String],
        seen: &mut BTreeSet<(usize, Name)>,
        owners: &mut BTreeSet<Name>,
    ) -> Option<Name> {
        if path.is_empty() || !seen.insert((scope, path.to_vec())) {
            return None;
        }

        let result = self.resolve_inner(scope, path, seen, owners);
        seen.remove(&(scope, path.to_vec()));

        result
    }

    fn resolve_inner(
        &self,
        scope: usize,
        path: &[String],
        seen: &mut BTreeSet<(usize, Name)>,
        owners: &mut BTreeSet<Name>,
    ) -> Option<Name> {
        let current = &self.scopes[scope];
        let mut rest = path;
        let mut target = match rest[0].as_str() {
            "::" => return None,
            "crate" => {
                rest = &rest[1..];
                Vec::new()
            }
            "self" => {
                rest = &rest[1..];
                current.module.clone()
            }
            "super" => {
                let mut target = current.module.clone();

                while rest.first().is_some_and(|part| part == "super") {
                    target.pop()?;
                    rest = &rest[1..];
                }

                target
            }
            first => {
                let mut lexical = Some(scope);
                let mut found = None;

                while let Some(index) = lexical {
                    let candidate = &self.scopes[index];
                    if candidate.names.contains(first) {
                        // Block-local names shadow imports but are not module members.
                        if candidate.parent.is_some() {
                            return None;
                        }

                        let mut name = candidate.module.clone();
                        name.push(first.to_owned());
                        found = Some(name);
                        break;
                    }

                    let named = candidate
                        .imports
                        .iter()
                        .find(|import| import.alias.as_deref() == Some(first));
                    if let Some(import) = named {
                        // An external alias must not fall through to an internal name.
                        found = Some(self.resolve(index, &import.path, seen, owners)?);
                        owners.insert(candidate.module.clone());
                        break;
                    }

                    for import in candidate
                        .imports
                        .iter()
                        .filter(|import| import.alias.is_none())
                    {
                        if let Some(mut base) = self.resolve(index, &import.path, seen, owners) {
                            if let Some(&module) = self.modules.get(&base) {
                                if let Some(name) =
                                    self.resolve(module, &[first.to_owned()], seen, owners)
                                {
                                    found = Some(name);
                                    owners.insert(candidate.module.clone());
                                    break;
                                }
                            } else {
                                // Glob-imported enum variants belong to the enum's module.
                                base.push(first.to_owned());
                                found = Some(base);
                                break;
                            }
                        }
                    }

                    if found.is_some() {
                        break;
                    }

                    lexical = candidate.parent;
                }

                rest = &rest[1..];
                found?
            }
        };

        for segment in rest {
            if let Some(&module) = self.modules.get(&target) {
                // Resolve re-exports and aliases in the module being traversed.
                target = self.resolve(module, std::slice::from_ref(segment), seen, owners)?;
            } else {
                target.push(segment.clone());
            }
        }

        Some(target)
    }

    fn edges(&self) -> Edges {
        let mut edges = Edges::new();

        for (scope, path) in
            self.paths
                .iter()
                .cloned()
                .chain(self.scopes.iter().enumerate().flat_map(|(scope, item)| {
                    item.imports
                        .iter()
                        .map(move |import| (scope, import.path.clone()))
                }))
        {
            let mut owners = BTreeSet::new();
            if let Some(target) = self.resolve(scope, &path, &mut BTreeSet::new(), &mut owners) {
                owners.insert(target);

                for mut target in owners {
                    while !self.modules.contains_key(&target) {
                        target.pop();
                    }

                    let source = &self.scopes[scope].module;
                    if source != &target {
                        edges.insert((source.clone(), target));
                    }
                }
            }
        }

        edges
    }
}

struct Paths<'a> {
    graph: &'a mut SourceGraph,
    scope: usize,
}

impl<'ast> Visit<'ast> for Paths<'_> {
    // pub(crate)/pub(super) restrict visibility; they do not use an ancestor.
    fn visit_visibility(&mut self, _: &'ast syn::Visibility) {}

    fn visit_item(&mut self, item: &'ast syn::Item) {
        if !skipped(item) {
            visit::visit_item(self, item);
        }
    }

    fn visit_item_mod(&mut self, _: &'ast syn::ItemMod) {}

    fn visit_item_use(&mut self, _: &'ast syn::ItemUse) {}

    fn visit_path(&mut self, path: &'ast syn::Path) {
        // Leading :: denotes an external crate in Rust 2018+, not this crate.
        if path.leading_colon.is_none() {
            self.graph.paths.push((
                self.scope,
                path.segments
                    .iter()
                    .map(|part| part.ident.to_string())
                    .collect(),
            ));
        }

        visit::visit_path(self, path);
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        let items: Vec<_> = block
            .stmts
            .iter()
            .filter_map(|stmt| {
                if let syn::Stmt::Item(item) = stmt {
                    Some(item.clone())
                } else {
                    None
                }
            })
            .collect();

        let previous = self.scope;
        self.scope = self.graph.scope(
            self.graph.scopes[previous].module.clone(),
            Some(previous),
            &items,
        );

        visit::visit_block(self, block);
        self.scope = previous;
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Violation {
    Ancestor(Name, Name),
    Cycle(Name, Name),
}

fn violations(edges: &Edges) -> BTreeSet<Violation> {
    let mut errors = BTreeSet::new();

    for (source, target) in edges {
        if source.starts_with(target) {
            errors.insert(Violation::Ancestor(source.clone(), target.clone()));
        }

        let mut pending = vec![target];
        let mut seen = BTreeSet::new();
        while let Some(node) = pending.pop() {
            if node == source {
                errors.insert(Violation::Cycle(source.clone(), target.clone()));
                break;
            }

            if seen.insert(node) {
                pending.extend(
                    edges
                        .iter()
                        .filter_map(|(from, to)| (from == node).then_some(to)),
                );
            }
        }
    }

    errors
}

#[test]
fn production_dependencies_have_no_ancestors_or_cycles() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let graph = SourceGraph::load(&root, &|path| {
        std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
    })
    .expect("parse production module tree");

    assert_eq!(violations(&graph.edges()), BTreeSet::new());
}

fn name(path: &str) -> Name {
    if path == "main" {
        Vec::new()
    } else {
        path.split("::").map(str::to_owned).collect()
    }
}

fn fixture(files: &[(&str, &str)]) -> SourceGraph {
    let files: BTreeMap<_, _> = files
        .iter()
        .map(|(path, source)| (PathBuf::from(path), source.to_string()))
        .collect();

    SourceGraph::load(Path::new("src/main.rs"), &|path| {
        files
            .get(path)
            .cloned()
            .ok_or_else(|| format!("missing fixture {}", path.display()))
    })
    .expect("parse test-owned module tree")
}

fn expected_edges(pairs: &[(&str, &str)]) -> Edges {
    pairs
        .iter()
        .map(|(from, to)| (name(from), name(to)))
        .collect()
}

#[test]
fn module_ownership_is_not_a_dependency_and_tests_are_excluded() {
    let graph = fixture(&[
        (
            "src/main.rs",
            "mod parent; #[cfg(test)] mod tests { use crate::parent; } mod behavior_tests;",
        ),
        ("src/parent.rs", "mod child;"),
        (
            "src/parent/child.rs",
            "pub(crate) struct Leaf; pub(super) fn run() {}",
        ),
    ]);

    assert_eq!(
        graph.modules.keys().cloned().collect::<BTreeSet<_>>(),
        [name("main"), name("parent"), name("parent::child")]
            .into_iter()
            .collect()
    );
    assert_eq!(graph.edges(), Edges::new());
}

#[test]
fn qualified_relative_and_root_items_detect_all_ancestors() {
    let graph = fixture(&[(
        "src/main.rs",
        r#"
        fn root_item() {}
        mod parent {
            pub struct Contract;
            mod child {
                fn run(_: super::Contract, _: crate::parent::Contract) {
                    crate::root_item();
                }
                mod leaf { fn run(_: super::super::Contract) {} }
            }
        }
    "#,
    )]);
    let edges = expected_edges(&[
        ("parent::child", "parent"),
        ("parent::child", "main"),
        ("parent::child::leaf", "parent"),
    ]);

    assert_eq!(graph.edges(), edges);
    assert_eq!(
        violations(&edges),
        [
            Violation::Ancestor(name("parent::child"), name("parent")),
            Violation::Ancestor(name("parent::child"), name("main")),
            Violation::Ancestor(name("parent::child::leaf"), name("parent")),
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn nested_use_trees_aliases_reexports_and_globs_resolve_to_owners() {
    let graph = fixture(&[(
        "src/main.rs",
        r#"
        mod contracts { pub struct Contract; }
        mod facade { pub use crate::contracts::{self as original, Contract as Export}; }
        mod consumer {
            use crate::{facade::{self as api, Export as Local}, contracts::*};
            fn run(_: Local, _: Contract, _: api::original::Contract) {
                use crate::contracts as inside;
                let _: inside::Contract;
            }
        }
    "#,
    )]);

    assert_eq!(
        graph.edges(),
        expected_edges(&[
            ("facade", "contracts"),
            ("consumer", "facade"),
            ("consumer", "contracts"),
        ])
    );
    assert!(violations(&graph.edges()).is_empty());
}

#[test]
fn imported_ancestor_aliases_and_globs_are_dependencies_even_when_unused() {
    let graph = fixture(&[(
        "src/main.rs",
        r#"
        struct Root;
        mod parent {
            pub struct Contract;
            mod child {
                use super::{self as owner, Contract as Alias};
                use owner::*;
                use crate::Root as RootAlias;
                fn run(_: Alias, _: RootAlias) {}
            }
        }
    "#,
    )]);

    assert_eq!(
        graph.edges(),
        expected_edges(&[("parent::child", "parent"), ("parent::child", "main")])
    );
    assert_eq!(violations(&graph.edges()).len(), 2);
}

#[test]
fn ancestor_reexports_cannot_hide_dependencies_on_their_owner() {
    let graph = fixture(&[(
        "src/main.rs",
        r#"
        mod parent {
            pub use self::child::Contract as Export;
            mod child {
                pub struct Contract;
                fn run(_: super::Export) {}
            }
        }
    "#,
    )]);

    assert_eq!(
        graph.edges(),
        expected_edges(&[("parent", "parent::child"), ("parent::child", "parent"),])
    );
    assert_eq!(
        violations(&graph.edges()),
        [
            Violation::Ancestor(name("parent::child"), name("parent")),
            Violation::Cycle(name("parent"), name("parent::child")),
            Violation::Cycle(name("parent::child"), name("parent")),
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn detects_direct_and_indirect_cycles_from_actual_paths() {
    let direct = fixture(&[(
        "src/main.rs",
        r#"
        mod a { pub struct A; fn run(_: crate::b::B) {} }
        mod b { pub struct B; use crate::a::A as Other; }
    "#,
    )]);

    assert_eq!(
        violations(&direct.edges()),
        [
            Violation::Cycle(name("a"), name("b")),
            Violation::Cycle(name("b"), name("a")),
        ]
        .into_iter()
        .collect()
    );

    let indirect = fixture(&[(
        "src/main.rs",
        r#"
        mod a { pub struct A; use crate::b::*; }
        mod b { pub struct B; fn run(_: crate::c::C) {} }
        mod c { pub struct C; use crate::a as back; fn run(_: back::A) {} }
    "#,
    )]);

    assert_eq!(
        violations(&indirect.edges()),
        [
            Violation::Cycle(name("a"), name("b")),
            Violation::Cycle(name("b"), name("c")),
            Violation::Cycle(name("c"), name("a")),
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn external_paths_comments_and_strings_do_not_create_dependencies() {
    let graph = fixture(&[(
        "src/main.rs",
        r#"
        extern crate dependency;
        mod process { pub struct Output; }
        mod leaf {
            use std::process as process;
            use std::collections::*;
            use ::process as external_process;
            extern crate other as another_external;
            fn run(_: process::Output, _: ::process::Output,
                   _: external_process::Output, _: another_external::Output,
                   _: crate::dependency::Output) {
                let _ = "crate::process::Output";
                // crate::process::Output
            }
        }
    "#,
    )]);

    assert_eq!(graph.edges(), Edges::new());
}

#[test]
fn cfg_test_items_do_not_add_production_edges() {
    let graph = fixture(&[(
        "src/main.rs",
        r#"
        struct Root;
        mod production {
            #[cfg(test)] struct TestOnly(crate::Root);
            #[cfg(test)] fn helper(_: crate::Root) {}
            #[test] fn example() { crate::root_item(); }
            #[cfg(all(test, unix))] mod nested { use crate::Root; }
        }
        fn root_item() {}
    "#,
    )]);

    assert_eq!(graph.edges(), Edges::new());
    assert_eq!(graph.modules.len(), 2);
}

#[test]
fn follows_flat_directory_inline_and_explicit_path_modules() {
    let graph = fixture(&[
        (
            "src/main.rs",
            "mod flat; mod directory; #[path = \"custom.rs\"] mod renamed; mod inline { mod child; }",
        ),
        ("src/flat.rs", "mod child;"),
        ("src/flat/child.rs", "use crate::renamed::Contract;"),
        ("src/directory/mod.rs", "mod child;"),
        ("src/directory/child.rs", "use crate::renamed::Contract;"),
        ("src/custom.rs", "pub struct Contract;"),
        ("src/inline/child.rs", "use crate::renamed::Contract;"),
    ]);

    assert_eq!(
        graph.edges(),
        expected_edges(&[
            ("flat::child", "renamed"),
            ("directory::child", "renamed"),
            ("inline::child", "renamed"),
        ])
    );
}
