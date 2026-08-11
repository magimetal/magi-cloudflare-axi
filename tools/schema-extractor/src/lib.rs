use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast_visit::{Visit, walk};
use oxc_index::Idx;
use oxc_parser::Parser;
use oxc_semantic::{Scoping, SemanticBuilder};
use oxc_span::{GetSpan, SourceType, Span};
use oxc_syntax::scope::ScopeFlags;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    path::Path,
    process::Command,
};

pub const EXTRACTOR_VERSION: &str = "phase1-oxc-0.6";
pub const COMMIT: &str = "70ff690553722f731849ede6ba9ce98958395a23";
pub const TREE: &str = "1a51c6ff07170dfe3c3212c8fb96eb85d66f0b96";
pub const CATALOG: &str = include_str!("../../../capabilities/cloudflare-mcp-parity.json");
const MAX_BLOB: usize = 8 * 1024 * 1024;
const MAX_DEPENDENCY_DEPTH: usize = 64;
const MAX_DEPENDENCY_CHAINS: usize = 4096;

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct SpanInfo {
    pub start_byte: u32,
    pub end_byte: u32,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct SemanticOccurrence {
    pub construct: String,
    pub signature: Option<String>,
    pub member_chain: Option<String>,
    pub file: String,
    pub blob_oid: String,
    pub span: SpanInfo,
    pub source_sha256: String,
    pub dependency_node_ids: Vec<String>,
    pub dependency_node_id: Option<String>,
    pub capabilities: Vec<String>,
    pub classification: String,
}
#[derive(Debug, Serialize, Clone)]
pub struct DirectBinding {
    pub name: String,
    pub classification: String,
    pub first_use: SpanInfo,
    pub declaration: Option<SpanInfo>,
    pub initializer_expression: Option<String>,
    pub initializer_span: Option<SpanInfo>,
    pub initializer_sha256: Option<String>,
    pub import_source: Option<String>,
    pub imported_name: Option<String>,
    pub import_declaration: Option<SpanInfo>,
    pub target_status: Option<String>,
    pub target_file: Option<String>,
    pub target_blob_oid: Option<String>,
    pub target_export_name: Option<String>,
    pub target_declaration: Option<SpanInfo>,
    pub target_initializer_expression: Option<String>,
    pub target_initializer_span: Option<SpanInfo>,
    pub target_initializer_sha256: Option<String>,
    pub dependency_root_id: Option<String>,
    pub dependency_closure_ids: Vec<String>,
    pub dependency_resolution_chains: Vec<Vec<String>>,
    pub dependency_max_depth: Option<usize>,
}

#[derive(Clone)]
struct ExportedValue {
    declaration: Span,
    initializer: Span,
}

struct TargetModule {
    source: String,
    exports: BTreeMap<String, Vec<ExportedValue>>,
}

#[derive(Clone)]
struct ModuleValue {
    name: String,
    declaration: Span,
    value: Span,
    value_kind: String,
    references: Vec<IdentifierReferenceInfo>,
}

#[derive(Clone)]
struct ModuleImport {
    local_name: String,
    classification: String,
    source: String,
    imported_name: String,
    declaration: Span,
}

#[derive(Clone)]
struct RuntimeBinding {
    name: String,
    declaration: Span,
    classification: String,
}

#[derive(Clone)]
struct ModuleIndex {
    source: String,
    blob_oid: String,
    values: HashMap<u32, ModuleValue>,
    imports: HashMap<u32, ModuleImport>,
    symbol_spans: HashMap<u32, Span>,
    runtime_bindings: HashMap<u32, RuntimeBinding>,
    exports: BTreeMap<String, Vec<u32>>,
    unsupported_exports: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct DependencyNode {
    pub id: String,
    pub name: String,
    pub file: String,
    pub blob_oid: String,
    pub value_kind: String,
    pub declaration: SpanInfo,
    pub value_span: SpanInfo,
    pub value_source: String,
    pub value_sha256: String,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct DependencyBoundary {
    pub id: String,
    pub name: String,
    pub classification: String,
    pub file: String,
    pub blob_oid: String,
    pub source_span_kind: String,
    pub source_span: SpanInfo,
    pub import_source: Option<String>,
    pub imported_name: Option<String>,
}

struct ExportIndexer {
    exports: BTreeMap<String, Vec<ExportedValue>>,
    error: Option<String>,
}

impl ExportIndexer {
    fn add<'a>(&mut self, declarator: &VariableDeclarator<'a>) {
        let Some(identifier) = declarator.id.get_binding_identifier() else {
            return;
        };
        let Some(initializer) = declarator.init.as_ref() else {
            return;
        };
        let Ok(name_len) = u32::try_from(identifier.name.len()) else {
            self.error = Some(format!("export name is too long: {}", identifier.name));
            return;
        };
        let Some(end) = identifier.span.start.checked_add(name_len) else {
            self.error = Some(format!(
                "export declaration span overflow: {}",
                identifier.name
            ));
            return;
        };
        self.exports
            .entry(identifier.name.to_string())
            .or_default()
            .push(ExportedValue {
                declaration: Span::new(identifier.span.start, end),
                initializer: initializer.span(),
            });
    }
}

impl<'a> Visit<'a> for ExportIndexer {
    fn visit_export_named_declaration(&mut self, export: &ExportNamedDeclaration<'a>) {
        if export.export_kind == ImportOrExportKind::Type {
            return;
        }
        if let Some(Declaration::VariableDeclaration(declaration)) = &export.declaration {
            for declarator in &declaration.declarations {
                self.add(declarator);
            }
        }
    }
}

fn target_exports(
    file: &str,
    source: &str,
) -> Result<BTreeMap<String, Vec<ExportedValue>>, String> {
    let allocator = Allocator::default();
    let parsed = Parser::new(
        &allocator,
        source,
        SourceType::default()
            .with_typescript(true)
            .with_module(true),
    )
    .parse();
    if parsed.panicked || !parsed.errors.is_empty() {
        return Err(format!(
            "target parser diagnostics in {file}: {}",
            parsed.errors.len()
        ));
    }
    let semantic = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(&parsed.program);
    if !semantic.errors.is_empty() {
        return Err(format!(
            "target semantic diagnostics in {file}: {}",
            semantic.errors.len()
        ));
    }
    let mut indexer = ExportIndexer {
        exports: BTreeMap::new(),
        error: None,
    };
    indexer.visit_program(&parsed.program);
    if let Some(error) = indexer.error {
        return Err(format!("target export provenance error in {file}: {error}"));
    }
    Ok(indexer.exports)
}

struct ModuleIndexer<'a> {
    reference_symbols: &'a HashMap<u32, u32>,
    values: HashMap<u32, ModuleValue>,
    imports: HashMap<u32, ModuleImport>,
    exports: BTreeMap<String, Vec<u32>>,
    runtime_bindings: HashMap<u32, RuntimeBinding>,
    unsupported_exports: BTreeMap<String, String>,
    error: Option<String>,
}

impl ModuleIndexer<'_> {
    fn add_value(&mut self, symbol: u32, name: &str, declaration: Span, value: Span, kind: &str) {
        let candidate = ModuleValue {
            name: name.into(),
            declaration,
            value,
            value_kind: kind.into(),
            references: Vec::new(),
        };
        if self.values.insert(symbol, candidate).is_some() {
            self.error = Some(format!(
                "duplicate value definition for symbol {symbol} ({name})"
            ));
        }
    }

    fn add_declarator(&mut self, declarator: &VariableDeclarator<'_>) {
        let Some(identifier) = declarator.id.get_binding_identifier() else {
            return;
        };
        let Some(symbol) = identifier.symbol_id.get() else {
            return;
        };
        let Some(initializer) = declarator.init.as_ref() else {
            return;
        };
        self.add_value(
            symbol.index() as u32,
            identifier.name.as_str(),
            identifier.span,
            initializer.span(),
            "variable_initializer",
        );
    }

    fn export_symbol(&mut self, exported: &str, symbol: u32) {
        self.exports
            .entry(exported.into())
            .or_default()
            .push(symbol);
    }
}

impl<'a> Visit<'a> for ModuleIndexer<'_> {
    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        self.add_declarator(declarator);
        walk::walk_variable_declarator(self, declarator);
    }

    fn visit_function(&mut self, function: &Function<'a>, flags: ScopeFlags) {
        if function.r#type == FunctionType::FunctionDeclaration {
            if let Some((identifier, symbol)) = function.id.as_ref().and_then(|identifier| {
                identifier
                    .symbol_id
                    .get()
                    .map(|symbol| (identifier, symbol))
            }) {
                self.add_value(
                    symbol.index() as u32,
                    identifier.name.as_str(),
                    identifier.span,
                    function.span,
                    "function_declaration",
                );
            }
        }
        walk::walk_function(self, function, flags);
    }

    fn visit_formal_parameter(&mut self, parameter: &FormalParameter<'a>) {
        if let Some((identifier, symbol)) =
            parameter
                .pattern
                .get_binding_identifier()
                .and_then(|identifier| {
                    identifier
                        .symbol_id
                        .get()
                        .map(|symbol| (identifier, symbol))
                })
        {
            self.runtime_bindings.insert(
                symbol.index() as u32,
                RuntimeBinding {
                    name: identifier.name.to_string(),
                    declaration: identifier.span,
                    classification: "lexical_parameter_boundary".into(),
                },
            );
        }
        walk::walk_formal_parameter(self, parameter);
    }

    fn visit_import_declaration(&mut self, declaration: &ImportDeclaration<'a>) {
        if declaration.import_kind != ImportOrExportKind::Type {
            for specifier in declaration.specifiers.iter().flatten() {
                if matches!(specifier, ImportDeclarationSpecifier::ImportSpecifier(specifier) if specifier.import_kind == ImportOrExportKind::Type)
                {
                    continue;
                }
                let (local, classification, imported_name) = match specifier {
                    ImportDeclarationSpecifier::ImportSpecifier(specifier) => (
                        &specifier.local,
                        "named_import",
                        module_name(&specifier.imported).map(str::to_owned),
                    ),
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(specifier) => {
                        (&specifier.local, "default_import", Some("default".into()))
                    }
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(specifier) => {
                        (&specifier.local, "namespace_import", Some("*".into()))
                    }
                };
                if let (Some(symbol), Some(imported_name)) = (local.symbol_id.get(), imported_name)
                {
                    self.imports.insert(
                        symbol.index() as u32,
                        ModuleImport {
                            local_name: local.name.to_string(),
                            classification: classification.into(),
                            source: declaration.source.value.to_string(),
                            imported_name,
                            declaration: declaration.span,
                        },
                    );
                }
            }
        }
        walk::walk_import_declaration(self, declaration);
    }

    fn visit_export_named_declaration(&mut self, export: &ExportNamedDeclaration<'a>) {
        if export.export_kind != ImportOrExportKind::Type {
            if let Some(declaration) = &export.declaration {
                match declaration {
                    Declaration::VariableDeclaration(declaration) => {
                        for declarator in &declaration.declarations {
                            if let Some((identifier, symbol)) = declarator
                                .id
                                .get_binding_identifier()
                                .and_then(|identifier| {
                                    identifier
                                        .symbol_id
                                        .get()
                                        .map(|symbol| (identifier, symbol))
                                })
                            {
                                self.export_symbol(identifier.name.as_str(), symbol.index() as u32);
                            }
                        }
                    }
                    Declaration::FunctionDeclaration(function) => {
                        if let Some((identifier, symbol)) =
                            function.id.as_ref().and_then(|identifier| {
                                identifier
                                    .symbol_id
                                    .get()
                                    .map(|symbol| (identifier, symbol))
                            })
                        {
                            self.export_symbol(identifier.name.as_str(), symbol.index() as u32);
                        }
                    }
                    _ => {}
                }
            }
            for specifier in &export.specifiers {
                if specifier.export_kind == ImportOrExportKind::Type {
                    continue;
                }
                let Some(exported) = module_name(&specifier.exported) else {
                    continue;
                };
                if export.source.is_some() {
                    self.unsupported_exports.insert(
                        exported.into(),
                        "named re-export dependency is unsupported".into(),
                    );
                    continue;
                }
                let symbol = match &specifier.local {
                    ModuleExportName::IdentifierReference(identifier) => {
                        reference_symbol(identifier, self.reference_symbols)
                    }
                    _ => None,
                };
                if let Some(symbol) = symbol {
                    self.export_symbol(exported, symbol);
                } else {
                    self.unsupported_exports.insert(
                        exported.into(),
                        "export specifier does not resolve to one local value".into(),
                    );
                }
            }
        }
        walk::walk_export_named_declaration(self, export);
    }
}

fn analyze_module(file: &str, source: String, blob_oid: String) -> Result<ModuleIndex, String> {
    let allocator = Allocator::default();
    let parsed = Parser::new(
        &allocator,
        &source,
        SourceType::default()
            .with_typescript(true)
            .with_module(true),
    )
    .parse();
    if parsed.panicked || !parsed.errors.is_empty() {
        return Err(format!(
            "dependency parser diagnostics in {file}: {}",
            parsed.errors.len()
        ));
    }
    let semantic_return = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(&parsed.program);
    if !semantic_return.errors.is_empty() {
        return Err(format!(
            "dependency semantic diagnostics in {file}: {}",
            semantic_return.errors.len()
        ));
    }
    let semantic = semantic_return.semantic;
    let mut reference_symbols = HashMap::new();
    for symbol in semantic.scoping().symbol_ids() {
        for reference in semantic.scoping().get_resolved_reference_ids(symbol) {
            reference_symbols.insert(reference.index() as u32, symbol.index() as u32);
        }
    }
    let references = {
        let mut collector = ReferenceCollector {
            reference_symbols: &reference_symbols,
            scoping: semantic.scoping(),
            references: Vec::new(),
        };
        collector.visit_program(&parsed.program);
        collector.references
    };
    let mut indexer = ModuleIndexer {
        reference_symbols: &reference_symbols,
        values: HashMap::new(),
        imports: HashMap::new(),
        exports: BTreeMap::new(),
        runtime_bindings: HashMap::new(),
        unsupported_exports: BTreeMap::new(),
        error: None,
    };
    indexer.visit_program(&parsed.program);
    if let Some(error) = indexer.error {
        return Err(format!("dependency index error in {file}: {error}"));
    }
    let symbol_spans = semantic
        .scoping()
        .symbol_ids()
        .map(|symbol| {
            (
                symbol.index() as u32,
                semantic.scoping().symbol_span(symbol),
            )
        })
        .collect();
    for value in indexer.values.values_mut() {
        value.references = references
            .iter()
            .filter(|reference| {
                reference.span.start >= value.value.start && reference.span.end <= value.value.end
            })
            .cloned()
            .collect();
    }
    Ok(ModuleIndex {
        source,
        blob_oid,
        values: indexer.values,
        imports: indexer.imports,
        exports: indexer.exports,
        runtime_bindings: indexer.runtime_bindings,
        unsupported_exports: indexer.unsupported_exports,
        symbol_spans,
    })
}

fn target_candidates(importer: &str, source: &str) -> Result<Vec<String>, String> {
    let base = if let Some(relative) = source.strip_prefix("@repo/mcp-common/src/") {
        format!("packages/mcp-common/src/{relative}")
    } else if source.starts_with("./") || source.starts_with("../") {
        let parent = Path::new(importer)
            .parent()
            .ok_or_else(|| format!("importer has no parent: {importer}"))?;
        parent.join(source).to_string_lossy().into_owned()
    } else {
        return Err(format!(
            "unsupported internal import source {source} in {importer}"
        ));
    };
    let mut parts = Vec::new();
    for part in base.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(format!(
                        "import escapes pinned tree: {source} in {importer}"
                    ));
                }
            }
            value => parts.push(value),
        }
    }
    let base = parts.join("/");
    Ok(if base.ends_with(".ts") {
        vec![base]
    } else {
        vec![format!("{base}.ts"), format!("{base}/index.ts")]
    })
}

fn hex_sha(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct DependencyResolver<'a> {
    root: &'a Path,
    tracked: &'a BTreeMap<String, String>,
    modules: HashMap<String, ModuleIndex>,
    nodes: BTreeMap<String, DependencyNode>,
    boundaries: BTreeMap<String, DependencyBoundary>,
    active: Vec<String>,
}

impl<'a> DependencyResolver<'a> {
    fn module(&mut self, file: &str) -> Result<ModuleIndex, String> {
        if let Some(module) = self.modules.get(file) {
            return Ok(module.clone());
        }
        let oid = self
            .tracked
            .get(file)
            .ok_or_else(|| format!("dependency file is not a regular pinned blob: {file}"))?;
        let blob = git(self.root, &["cat-file", "blob", oid])?;
        if blob.len() > MAX_BLOB {
            return Err(format!("dependency blob exceeds bound: {file}"));
        }
        let source = String::from_utf8(blob)
            .map_err(|_| format!("invalid UTF-8 dependency blob: {file}"))?;
        let module = analyze_module(file, source, oid.clone())?;
        self.modules.insert(file.into(), module.clone());
        Ok(module)
    }

    fn exported_symbol(&mut self, file: &str, exported: &str) -> Result<u32, String> {
        let module = self.module(file)?;
        let symbols = module.exports.get(exported).ok_or_else(|| {
            module.unsupported_exports.get(exported).map_or_else(
                || format!("dependency export {exported} missing in {file}"),
                |reason| format!("unsupported dependency export {exported} in {file}: {reason}"),
            )
        })?;
        if symbols.len() != 1 {
            return Err(format!(
                "dependency export {exported} in {file} must resolve exactly once"
            ));
        }
        let symbol = symbols[0];
        if !module.values.contains_key(&symbol) {
            return Err(format!(
                "dependency export {exported} in {file} is not an initialized value"
            ));
        }
        Ok(symbol)
    }

    fn internal_target(&self, importer: &str, source: &str) -> Result<String, String> {
        let matches = target_candidates(importer, source)?
            .into_iter()
            .filter(|candidate| self.tracked.contains_key(candidate))
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(format!(
                "dependency import target must resolve exactly once: {source} from {importer} matched {matches:?}"
            ));
        }
        Ok(matches[0].clone())
    }

    fn boundary(&mut self, boundary: DependencyBoundary) -> Result<String, String> {
        let id = boundary.id.clone();
        if let Some(existing) = self.boundaries.get(&id) {
            if existing != &boundary {
                return Err(format!(
                    "conflicting dependency boundary metadata for {id}: {existing:?} != {boundary:?}"
                ));
            }
        } else {
            self.boundaries.insert(id.clone(), boundary);
        }
        Ok(id)
    }

    fn resolve_import(
        &mut self,
        importer: &str,
        module: &ModuleIndex,
        import: &ModuleImport,
        depth: usize,
    ) -> Result<String, String> {
        if import.source.starts_with('.') || import.source.starts_with("@repo/") {
            if import.classification != "named_import" {
                return Err(format!(
                    "unsupported internal {} dependency {} from {} in {} at bytes {}..{}",
                    import.classification,
                    import.local_name,
                    import.source,
                    importer,
                    import.declaration.start,
                    import.declaration.end
                ));
            }
            let target = self.internal_target(importer, &import.source)?;
            let symbol = self.exported_symbol(&target, &import.imported_name)?;
            self.resolve_value(&target, symbol, depth)
        } else {
            let id = format!(
                "external-package:{}:{}-{}:{}:{}",
                importer,
                import.declaration.start,
                import.declaration.end,
                import.source,
                import.imported_name
            );
            self.boundary(DependencyBoundary {
                id,
                name: import.local_name.clone(),
                classification: "external_package_boundary".into(),
                file: importer.into(),
                blob_oid: module.blob_oid.clone(),
                source_span_kind: "import_declaration".into(),
                source_span: span_info(import.declaration, &module.source),
                import_source: Some(import.source.clone()),
                imported_name: Some(import.imported_name.clone()),
            })
        }
    }

    fn resolve_reference(
        &mut self,
        file: &str,
        module: &ModuleIndex,
        owner: &ModuleValue,
        reference: &IdentifierReferenceInfo,
        depth: usize,
    ) -> Result<Option<String>, String> {
        let Some(symbol) = reference.symbol else {
            if [
                "Boolean", "Date", "Error", "Math", "Object", "Set", "URL", "isNaN", "parseInt",
            ]
            .contains(&reference.name.as_str())
            {
                let id = format!(
                    "language-builtin:{}:{}-{}:{}",
                    file, reference.span.start, reference.span.end, reference.name
                );
                return self
                    .boundary(DependencyBoundary {
                        id,
                        name: reference.name.clone(),
                        classification: "language_builtin_boundary".into(),
                        file: file.into(),
                        blob_oid: module.blob_oid.clone(),
                        source_span_kind: "identifier_reference".into(),
                        source_span: span_info(reference.span, &module.source),
                        import_source: None,
                        imported_name: None,
                    })
                    .map(Some);
            }
            return Err(format!(
                "unsupported unresolved global dependency {} in {} value {}",
                reference.name, file, owner.name
            ));
        };
        if module.symbol_spans.get(&symbol).is_some_and(|declaration| {
            declaration.start >= owner.value.start && declaration.end <= owner.value.end
        }) {
            return Ok(None);
        }
        if module.values.contains_key(&symbol) {
            return self.resolve_value(file, symbol, depth).map(Some);
        }
        if let Some(import) = module.imports.get(&symbol) {
            return self.resolve_import(file, module, import, depth).map(Some);
        }
        if let Some(runtime) = module.runtime_bindings.get(&symbol) {
            let id = format!(
                "{}:{}:{}-{}:{}",
                runtime.classification,
                file,
                runtime.declaration.start,
                runtime.declaration.end,
                runtime.name
            );
            return self
                .boundary(DependencyBoundary {
                    id,
                    name: runtime.name.clone(),
                    classification: runtime.classification.clone(),
                    file: file.into(),
                    blob_oid: module.blob_oid.clone(),
                    source_span_kind: "parameter_declaration".into(),
                    source_span: span_info(runtime.declaration, &module.source),
                    import_source: None,
                    imported_name: None,
                })
                .map(Some);
        }
        Err(format!(
            "unsupported local dependency {} in {} value {}",
            reference.name, file, owner.name
        ))
    }

    fn resolve_value(&mut self, file: &str, symbol: u32, depth: usize) -> Result<String, String> {
        if depth > MAX_DEPENDENCY_DEPTH {
            return Err(format!(
                "dependency depth exceeds {MAX_DEPENDENCY_DEPTH} while resolving {file}"
            ));
        }
        let module = self.module(file)?;
        let value = module.values.get(&symbol).cloned().ok_or_else(|| {
            format!("dependency symbol {symbol} in {file} has no supported value declaration")
        })?;
        let id = format!(
            "{}:{}-{}:{}",
            file, value.declaration.start, value.declaration.end, value.name
        );
        if let Some(position) = self.active.iter().position(|active| active == &id) {
            let mut cycle = self.active[position..].to_vec();
            cycle.push(id.clone());
            return Err(format!("dependency cycle: {}", cycle.join(" -> ")));
        }
        if self.nodes.contains_key(&id) {
            return Ok(id);
        }
        if value.value.start > value.value.end || value.value.end as usize > module.source.len() {
            return Err(format!("invalid dependency value bounds for {id}"));
        }
        self.active.push(id.clone());
        let mut references = value.references.clone();
        references.sort_by_key(|reference| (reference.span.start, reference.span.end));
        let mut dependencies = BTreeSet::new();
        for reference in &references {
            if let Some(dependency) =
                self.resolve_reference(file, &module, &value, reference, depth + 1)?
            {
                dependencies.insert(dependency);
            }
        }
        let popped = self.active.pop();
        if popped.as_deref() != Some(id.as_str()) {
            return Err("dependency traversal stack corruption".into());
        }
        let value_source =
            module.source[value.value.start as usize..value.value.end as usize].to_string();
        self.nodes.insert(
            id.clone(),
            DependencyNode {
                id: id.clone(),
                name: value.name,
                file: file.into(),
                blob_oid: module.blob_oid,
                value_kind: value.value_kind,
                declaration: span_info(value.declaration, &module.source),
                value_span: span_info(value.value, &module.source),
                value_sha256: hex_sha(&value_source),
                value_source,
                dependencies: dependencies.into_iter().collect(),
            },
        );
        Ok(id)
    }

    fn closure(&self, root: &str) -> Result<Vec<String>, String> {
        let mut seen = BTreeSet::new();
        let mut pending = vec![root.to_string()];
        while let Some(id) = pending.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            if let Some(node) = self.nodes.get(&id) {
                for dependency in node.dependencies.iter().rev() {
                    pending.push(dependency.clone());
                }
            } else if !self.boundaries.contains_key(&id) {
                return Err(format!("dependency closure references missing node {id}"));
            }
        }
        Ok(seen.into_iter().collect())
    }

    fn resolution_chains(&self, root: &str) -> Result<Vec<Vec<String>>, String> {
        let mut chains = Vec::new();
        let mut pending = vec![vec![root.to_string()]];
        while let Some(chain) = pending.pop() {
            let depth = chain.len().saturating_sub(1);
            if depth > MAX_DEPENDENCY_DEPTH {
                return Err(format!(
                    "dependency depth exceeds {MAX_DEPENDENCY_DEPTH} for {root}: {}",
                    chain.join(" -> ")
                ));
            }
            if chains.len() + pending.len() >= MAX_DEPENDENCY_CHAINS {
                return Err(format!(
                    "dependency resolution chains exceed {MAX_DEPENDENCY_CHAINS} for {root}"
                ));
            }
            let current = chain
                .last()
                .ok_or("dependency resolution produced an empty chain")?;
            if let Some(node) = self.nodes.get(current) {
                if node.dependencies.is_empty() {
                    chains.push(chain);
                } else {
                    for dependency in node.dependencies.iter().rev() {
                        let mut next = chain.clone();
                        next.push(dependency.clone());
                        pending.push(next);
                    }
                }
            } else if self.boundaries.contains_key(current) {
                chains.push(chain);
            } else {
                return Err(format!(
                    "dependency chain references missing node {current}"
                ));
            }
        }
        chains.sort();
        Ok(chains)
    }
}

fn resolve_dependency_closures(
    root: &Path,
    tracked: &BTreeMap<String, String>,
    records: &mut [Record],
) -> Result<(Vec<DependencyNode>, Vec<DependencyBoundary>), String> {
    let mut resolver = DependencyResolver {
        root,
        tracked,
        modules: HashMap::new(),
        nodes: BTreeMap::new(),
        boundaries: BTreeMap::new(),
        active: Vec::new(),
    };
    for record in records {
        for binding in &mut record.direct_bindings {
            let target_file = binding
                .target_file
                .as_deref()
                .ok_or_else(|| format!("dependency root {} missing target file", binding.name))?;
            let module = resolver.module(target_file)?;
            let symbol = if binding.target_status.as_deref() == Some("same_file_value") {
                let declaration = binding.declaration.as_ref().ok_or_else(|| {
                    format!(
                        "same-file dependency root {} missing declaration",
                        binding.name
                    )
                })?;
                let matches = module
                    .values
                    .iter()
                    .filter(|(_, value)| {
                        value.declaration.start == declaration.start_byte
                            && value.declaration.end == declaration.end_byte
                    })
                    .map(|(symbol, _)| *symbol)
                    .collect::<Vec<_>>();
                if matches.len() != 1 {
                    return Err(format!(
                        "same-file dependency root {} in {} must resolve exactly once",
                        binding.name, target_file
                    ));
                }
                matches[0]
            } else if binding.target_status.as_deref() == Some("pinned_internal_value") {
                let exported = binding.target_export_name.as_deref().ok_or_else(|| {
                    format!(
                        "imported dependency root {} missing export name",
                        binding.name
                    )
                })?;
                resolver.exported_symbol(target_file, exported)?
            } else {
                return Err(format!(
                    "unsupported dependency root status for {}: {:?}",
                    binding.name, binding.target_status
                ));
            };
            let root_id = resolver.resolve_value(target_file, symbol, 0)?;
            let closure = resolver.closure(&root_id)?;
            let chains = resolver.resolution_chains(&root_id)?;
            let max_depth = chains
                .iter()
                .map(|chain| chain.len().saturating_sub(1))
                .max()
                .unwrap_or(0);
            binding.dependency_root_id = Some(root_id);
            binding.dependency_closure_ids = closure;
            binding.dependency_resolution_chains = chains;
            binding.dependency_max_depth = Some(max_depth);
        }
    }
    Ok((
        resolver.nodes.into_values().collect(),
        resolver.boundaries.into_values().collect(),
    ))
}

fn resolve_named_imports(
    root: &Path,
    tracked: &BTreeMap<String, String>,
    records: &mut [Record],
) -> Result<BTreeMap<String, usize>, String> {
    let mut cache = HashMap::<String, TargetModule>::new();
    let mut statuses = BTreeMap::new();
    for record in records {
        for binding in &mut record.direct_bindings {
            if binding.classification == "same_file_initializer" {
                binding.target_status = Some("same_file_value".into());
                binding.target_file = Some(record.file.clone());
                binding.target_blob_oid = Some(record.blob_oid.clone());
                *statuses.entry("same_file_value".into()).or_insert(0) += 1;
                continue;
            }
            if binding.classification != "named_import" {
                continue;
            }
            let import_source = binding
                .import_source
                .as_deref()
                .ok_or_else(|| format!("named import {} missing source", binding.name))?;
            if !import_source.starts_with('.') && !import_source.starts_with("@repo/") {
                binding.target_status = Some("external_package_boundary".into());
                *statuses
                    .entry("external_package_boundary".into())
                    .or_insert(0) += 1;
                continue;
            }
            let candidates = target_candidates(&record.file, import_source)?;
            let matches = candidates
                .iter()
                .filter_map(|path| tracked.get(path).map(|oid| (path.clone(), oid.clone())))
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return Err(format!(
                    "internal import target must resolve exactly once: {} from {} matched {:?}",
                    import_source, record.file, matches
                ));
            }
            let (target_file, target_oid) = &matches[0];
            if !cache.contains_key(target_file) {
                let blob = git(root, &["cat-file", "blob", target_oid])?;
                if blob.len() > MAX_BLOB {
                    return Err(format!("target blob exceeds bound: {target_file}"));
                }
                let source = String::from_utf8(blob)
                    .map_err(|_| format!("invalid UTF-8 target blob: {target_file}"))?;
                let exports = target_exports(target_file, &source)?;
                cache.insert(target_file.clone(), TargetModule { source, exports });
            }
            let module = cache
                .get(target_file)
                .ok_or_else(|| format!("target cache failure: {target_file}"))?;
            let imported = binding
                .imported_name
                .as_deref()
                .ok_or_else(|| format!("named import {} missing imported name", binding.name))?;
            let values = module.exports.get(imported).ok_or_else(|| {
                format!("exported initialized value {imported} missing in {target_file}")
            })?;
            if values.len() != 1 {
                return Err(format!(
                    "exported initialized value {imported} ambiguous in {target_file}"
                ));
            }
            let value = &values[0];
            if value.initializer.start > value.initializer.end
                || value.initializer.end as usize > module.source.len()
            {
                return Err(format!(
                    "invalid target initializer bounds for {imported} in {target_file}"
                ));
            }
            let expression = module.source
                [value.initializer.start as usize..value.initializer.end as usize]
                .to_string();
            binding.target_status = Some("pinned_internal_value".into());
            binding.target_file = Some(target_file.clone());
            binding.target_blob_oid = Some(target_oid.clone());
            binding.target_export_name = Some(imported.to_string());
            binding.target_declaration = Some(span_info(value.declaration, &module.source));
            binding.target_initializer_expression = Some(expression.clone());
            binding.target_initializer_span = Some(span_info(value.initializer, &module.source));
            binding.target_initializer_sha256 = Some(hex_sha(&expression));
            *statuses.entry("pinned_internal_value".into()).or_insert(0) += 1;
        }
    }
    Ok(statuses)
}
#[derive(Debug, Serialize, Clone)]
pub struct Record {
    pub name: String,
    pub file: String,
    pub blob_oid: String,
    pub registration_span: SpanInfo,
    pub schema_span: Option<SpanInfo>,
    pub registration_kind: String,
    pub schema_root_kind: String,
    pub schema_expression_kind: String,
    pub schema_syntax_features: Vec<String>,
    pub semantic_occurrences: Vec<SemanticOccurrence>,
    pub schema_expression: Option<String>,
    pub schema_expression_sha256: Option<String>,
    pub direct_bindings: Vec<DirectBinding>,
    pub referenced_bindings: Vec<String>,
    pub resolution_status: String,
    pub resolution_reason: Option<String>,
}
struct SyntaxInfo {
    kind: String,
    features: Vec<String>,
    occurrences: Vec<SyntaxOccurrence>,
}
#[derive(Clone)]
struct SyntaxOccurrence {
    construct: String,
    signature: Option<String>,
    member_chain: Option<String>,
    span: Span,
    classification: String,
}
struct SyntaxIndexer<'a> {
    zod_symbols: &'a HashSet<u32>,
    reference_symbols: &'a HashMap<u32, u32>,
    syntax: HashMap<(u32, u32), SyntaxInfo>,
}
impl<'a> Visit<'a> for SyntaxIndexer<'a> {
    fn visit_expression(&mut self, expression: &Expression<'a>) {
        let mut collector = SyntaxCollector {
            zod_symbols: self.zod_symbols,
            reference_symbols: self.reference_symbols,
            features: BTreeSet::new(),
            occurrences: Vec::new(),
        };
        collector.visit_expression(expression);
        let kind = match expression {
            Expression::CallExpression(call)
                if matches!(&call.callee, Expression::StaticMemberExpression(member)
                if ident(&member.object).and_then(|z| reference_symbol(z, self.reference_symbols))
                    .is_some_and(|symbol| self.zod_symbols.contains(&symbol)) && member.property.name == "object") =>
            {
                "zod_object_call"
            }
            Expression::ObjectExpression(_) => "object_shape",
            _ => "unknown",
        };
        self.syntax.insert(
            (expression.span().start, expression.span().end),
            SyntaxInfo {
                kind: kind.into(),
                features: collector.features.into_iter().collect(),
                occurrences: collector.occurrences,
            },
        );
        walk::walk_expression(self, expression);
    }
}
struct SyntaxCollector<'a> {
    zod_symbols: &'a HashSet<u32>,
    reference_symbols: &'a HashMap<u32, u32>,
    features: BTreeSet<String>,
    occurrences: Vec<SyntaxOccurrence>,
}
impl<'a> SyntaxCollector<'a> {
    fn zod_factory(&mut self, call: &CallExpression<'a>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        let Some(object) = ident(&member.object) else {
            return;
        };
        if reference_symbol(object, self.reference_symbols)
            .is_some_and(|symbol| self.zod_symbols.contains(&symbol))
        {
            self.features
                .insert(format!("zod_factory_call:z.{}", member.property.name));
        }
    }
    fn classification(&self, call: &CallExpression<'a>) -> &'static str {
        let Some(chain) = static_chain(&call.callee) else {
            return "helper_runtime";
        };
        let Some(identifier) = root_identifier(&call.callee) else {
            return "helper_runtime";
        };
        let Some(symbol) = reference_symbol(identifier, self.reference_symbols) else {
            return "helper_runtime";
        };
        if !self.zod_symbols.contains(&symbol)
            && !is_zod_chain(&call.callee, self.reference_symbols, self.zod_symbols)
        {
            return if identifier.name == "z" {
                "shadowed_foreign"
            } else {
                "helper_runtime"
            };
        }
        let segments = chain.split('.').collect::<Vec<_>>();
        if segments.len() == 2 {
            return "zod_factory";
        }
        match segments
            .last()
            .copied()
            .unwrap_or_default()
            .trim_end_matches("()")
        {
            "refine" | "superRefine" => "zod_refinement",
            "transform" => "zod_transform",
            _ => "zod_modifier",
        }
    }
}
impl<'a> Visit<'a> for SyntaxCollector<'a> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        self.zod_factory(call);
        match &call.callee {
            Expression::Identifier(identifier) => {
                self.features
                    .insert(format!("identifier_call:{}", identifier.name));
            }
            Expression::StaticMemberExpression(member) => {
                self.features
                    .insert(format!("static_method:{}", member.property.name));
            }
            _ => {
                self.features.insert("dynamic_call".into());
            }
        }
        walk::walk_call_expression(self, call);
    }
    fn visit_identifier_reference(&mut self, identifier: &IdentifierReference<'a>) {
        self.features.insert("identifier_reference".into());
        walk::walk_identifier_reference(self, identifier);
    }
    fn visit_object_expression(&mut self, object: &ObjectExpression<'a>) {
        if object
            .properties
            .iter()
            .any(|property| matches!(property, ObjectPropertyKind::SpreadProperty(_)))
        {
            self.features.insert("object_spread".into());
        }
        walk::walk_object_expression(self, object);
    }
    fn visit_array_expression(&mut self, array: &ArrayExpression<'a>) {
        if array
            .elements
            .iter()
            .any(|element| matches!(element, ArrayExpressionElement::SpreadElement(_)))
        {
            self.features.insert("array_spread".into());
        }
        walk::walk_array_expression(self, array);
    }
    fn visit_object_property(&mut self, property: &ObjectProperty<'a>) {
        if property.computed {
            self.features.insert("computed_property".into());
        }
        walk::walk_object_property(self, property);
    }
    fn visit_expression(&mut self, expression: &Expression<'a>) {
        match expression {
            Expression::ArrowFunctionExpression(_) => {
                self.features.insert("arrow_function".into());
            }
            Expression::FunctionExpression(_) => {
                self.features.insert("function_expression".into());
            }
            Expression::ConditionalExpression(_) => {
                self.features.insert("conditional_expression".into());
            }
            _ => {}
        }
        let (construct, signature, member_chain) = match expression {
            Expression::CallExpression(call) => (
                "call",
                static_chain(&call.callee).map(|chain| format!("{chain}()")),
                None,
            ),
            Expression::StaticMemberExpression(_) => {
                ("member_chain", None, static_chain(expression))
            }
            Expression::ComputedMemberExpression(_) => ("computed_member", None, None),
            Expression::ObjectExpression(object) => (
                if object
                    .properties
                    .iter()
                    .any(|p| matches!(p, ObjectPropertyKind::SpreadProperty(_)))
                {
                    "object_spread"
                } else {
                    "object"
                },
                None,
                None,
            ),
            Expression::ArrayExpression(array) => (
                if array
                    .elements
                    .iter()
                    .any(|e| matches!(e, ArrayExpressionElement::SpreadElement(_)))
                {
                    "array_spread"
                } else {
                    "array"
                },
                None,
                None,
            ),
            Expression::ArrowFunctionExpression(_) => ("arrow_function", None, None),
            Expression::FunctionExpression(_) => ("function_expression", None, None),
            Expression::ConditionalExpression(_) => ("conditional", None, None),
            Expression::BinaryExpression(_)
            | Expression::LogicalExpression(_)
            | Expression::UnaryExpression(_)
            | Expression::UpdateExpression(_) => ("operator", None, None),
            Expression::StringLiteral(_) => ("string_literal", None, None),
            Expression::NumericLiteral(_) => ("numeric_literal", None, None),
            Expression::BooleanLiteral(_) => ("boolean_literal", None, None),
            Expression::NullLiteral(_) => ("null_literal", None, None),
            Expression::TemplateLiteral(_) => ("template_literal", None, None),
            Expression::Identifier(_) => ("identifier", None, None),
            _ => ("unsupported_ast_form", None, None),
        };
        let classification = if construct == "unsupported_ast_form" {
            "unsupported_for_canonical_compile"
        } else if construct == "call" && signature.as_deref().is_some_and(|s| s.starts_with("z.")) {
            self.classification(match expression {
                Expression::CallExpression(call) => call,
                _ => unreachable!(),
            })
        } else if construct == "call" || construct == "computed_member" {
            "helper_runtime"
        } else if construct == "member_chain" {
            "member_access_context"
        } else {
            "candidate_representable"
        };
        self.occurrences.push(SyntaxOccurrence {
            construct: construct.into(),
            signature,
            member_chain,
            span: expression.span(),
            classification: classification.into(),
        });
        walk::walk_expression(self, expression);
    }
}
fn static_chain(expression: &Expression<'_>) -> Option<String> {
    match expression {
        Expression::Identifier(identifier) => Some(identifier.name.to_string()),
        Expression::StaticMemberExpression(member) => Some(format!(
            "{}.{}",
            static_chain(&member.object)?,
            member.property.name
        )),
        Expression::CallExpression(call) => Some(format!("{}()", static_chain(&call.callee)?)),
        _ => None,
    }
}
fn root_identifier<'a>(expression: &'a Expression<'a>) -> Option<&'a IdentifierReference<'a>> {
    match expression {
        Expression::Identifier(identifier) => Some(identifier),
        Expression::StaticMemberExpression(member) => root_identifier(&member.object),
        Expression::CallExpression(call) => root_identifier(&call.callee),
        _ => None,
    }
}
fn is_zod_chain(
    expression: &Expression<'_>,
    references: &HashMap<u32, u32>,
    zod: &HashSet<u32>,
) -> bool {
    match expression {
        Expression::StaticMemberExpression(member) => match &member.object {
            Expression::Identifier(identifier) => {
                reference_symbol(identifier, references).is_some_and(|symbol| zod.contains(&symbol))
            }
            _ => is_zod_chain(&member.object, references, zod),
        },
        Expression::CallExpression(call) => is_zod_chain(&call.callee, references, zod),
        _ => false,
    }
}
#[derive(Debug, Serialize, Clone)]
pub struct SemanticOccurrenceRegistryEntry {
    pub construct: String,
    pub signature: Option<String>,
    pub member_chain: Option<String>,
    pub file: String,
    pub blob_oid: String,
    pub span: SpanInfo,
    pub source_sha256: String,
    pub dependency_node_id: Option<String>,
    pub capabilities: Vec<String>,
    pub classification: String,
}
#[derive(Debug, Serialize)]
pub struct Census {
    pub version: String,
    pub extractor_version: String,
    pub provenance_claim: String,
    pub source_access: String,
    pub schema_semantics: String,
    pub parser: String,
    pub source_commit: String,
    pub tree_oid: String,
    pub zod_version: Option<String>,
    pub file_count: usize,
    pub semantic_unknown_construct_counts: BTreeMap<String, usize>,
    pub semantic_unsupported_construct_counts: BTreeMap<String, usize>,
    pub catalog_count: usize,
    pub source_count: usize,
    pub duplicates: Vec<String>,
    pub missing: Vec<String>,
    pub extra: Vec<String>,
    pub expression_kind_counts: BTreeMap<String, usize>,
    pub feature_record_counts: BTreeMap<String, usize>,
    pub semantic_construct_counts: BTreeMap<String, usize>,
    pub semantic_classification_counts: BTreeMap<String, usize>,
    pub direct_binding_kind_counts: BTreeMap<String, usize>,
    pub target_status_counts: BTreeMap<String, usize>,
    pub dependency_node_count: usize,
    pub dependency_edge_count: usize,
    pub dependency_resolution_chain_count: usize,
    pub dependency_max_depth: usize,
    pub distinct_dependency_value_hash_count: usize,
    pub dependency_value_kind_counts: BTreeMap<String, usize>,
    pub dependency_boundary_kind_counts: BTreeMap<String, usize>,
    pub unsupported_dependency_construct_counts: BTreeMap<String, usize>,
    pub semantic_occurrence_registry: Vec<SemanticOccurrenceRegistryEntry>,
    pub dependency_nodes: Vec<DependencyNode>,
    pub dependency_boundaries: Vec<DependencyBoundary>,
    pub records: Vec<Record>,
}

fn span_info(span: Span, source: &str) -> SpanInfo {
    let line = |p: usize| {
        source[..p.min(source.len())]
            .bytes()
            .filter(|b| *b == b'\n')
            .count()
            + 1
    };
    SpanInfo {
        start_byte: span.start,
        end_byte: span.end,
        start_line: line(span.start as usize),
        end_line: line(span.end as usize),
    }
}
fn ident<'a>(e: &'a Expression<'a>) -> Option<&'a IdentifierReference<'a>> {
    if let Expression::Identifier(x) = e {
        Some(x)
    } else {
        None
    }
}
fn key_name<'a>(key: &'a PropertyKey<'a>) -> Option<&'a str> {
    match key {
        PropertyKey::StaticIdentifier(x) => Some(x.name.as_str()),
        PropertyKey::StringLiteral(x) => Some(x.value.as_str()),
        _ => None,
    }
}
fn module_name<'a>(name: &'a ModuleExportName<'a>) -> Option<&'a str> {
    match name {
        ModuleExportName::IdentifierName(x) => Some(x.name.as_str()),
        ModuleExportName::IdentifierReference(x) => Some(x.name.as_str()),
        ModuleExportName::StringLiteral(x) => Some(x.value.as_str()),
    }
}
fn property<'a>(object: &'a ObjectExpression<'a>, name: &str) -> Option<&'a ObjectProperty<'a>> {
    object
        .properties
        .iter()
        .find_map(|property| match property {
            ObjectPropertyKind::ObjectProperty(property)
                if key_name(&property.key) == Some(name) =>
            {
                Some(&**property)
            }
            _ => None,
        })
}
fn binding_symbol(pattern: &BindingPattern<'_>) -> Option<u32> {
    pattern
        .get_binding_identifier()
        .and_then(|identifier| identifier.symbol_id.get())
        .map(|symbol| symbol.index() as u32)
}
fn object_binding_symbol(pattern: &BindingPattern<'_>, name: &str) -> Option<u32> {
    let BindingPatternKind::ObjectPattern(object) = &pattern.kind else {
        return None;
    };
    object
        .properties
        .iter()
        .find(|property| key_name(&property.key) == Some(name))
        .and_then(|property| binding_symbol(&property.value))
}
struct ZodImportCollector {
    symbols: HashSet<u32>,
}

impl<'a> Visit<'a> for ZodImportCollector {
    fn visit_import_declaration(&mut self, declaration: &ImportDeclaration<'a>) {
        if declaration.source.value == "zod" && declaration.import_kind != ImportOrExportKind::Type
        {
            for specifier in declaration.specifiers.iter().flatten() {
                let local = match specifier {
                    ImportDeclarationSpecifier::ImportSpecifier(specifier)
                        if specifier.import_kind != ImportOrExportKind::Type
                            && module_name(&specifier.imported) == Some("z") =>
                    {
                        Some(&specifier.local)
                    }
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(specifier) => {
                        Some(&specifier.local)
                    }
                    _ => None,
                };
                if let Some(symbol) = local.and_then(|local| local.symbol_id.get()) {
                    self.symbols.insert(symbol.index() as u32);
                }
            }
        }
        walk::walk_import_declaration(self, declaration);
    }
}

fn surveyed_syntax(source: &str) -> Result<Vec<SyntaxOccurrence>, String> {
    let allocator = Allocator::default();
    let parsed = Parser::new(
        &allocator,
        source,
        SourceType::default()
            .with_typescript(true)
            .with_module(true),
    )
    .parse();
    if parsed.panicked || !parsed.errors.is_empty() {
        return Err(format!(
            "dependency survey parser diagnostics: {}",
            parsed.errors.len()
        ));
    }
    let semantic_return = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(&parsed.program);
    if !semantic_return.errors.is_empty() {
        return Err(format!(
            "dependency survey semantic diagnostics: {}",
            semantic_return.errors.len()
        ));
    }
    let semantic = semantic_return.semantic;
    let mut references = HashMap::new();
    for symbol in semantic.scoping().symbol_ids() {
        for reference in semantic.scoping().get_resolved_reference_ids(symbol) {
            references.insert(reference.index() as u32, symbol.index() as u32);
        }
    }
    let mut zod_imports = ZodImportCollector {
        symbols: HashSet::new(),
    };
    zod_imports.visit_program(&parsed.program);
    let mut collector = SyntaxCollector {
        zod_symbols: &zod_imports.symbols,
        reference_symbols: &references,
        features: BTreeSet::new(),
        occurrences: Vec::new(),
    };
    collector.visit_program(&parsed.program);
    Ok(collector.occurrences)
}
fn reference_symbol(
    identifier: &IdentifierReference<'_>,
    reference_symbols: &HashMap<u32, u32>,
) -> Option<u32> {
    identifier
        .reference_id
        .get()
        .and_then(|reference| reference_symbols.get(&(reference.index() as u32)).copied())
}

#[derive(Clone)]
struct CasbDefinition {
    name: String,
    params: Span,
}

#[derive(Clone, Debug)]
struct BindingMetadata {
    classification: String,
    declaration: Span,
    initializer: Option<Span>,
    import_source: Option<String>,
    imported_name: Option<String>,
    import_declaration: Option<Span>,
}
#[derive(Clone)]
struct CasbCallback {
    registration_spans: Vec<Span>,
    definitions_symbol: u32,
    name_symbol: u32,
    params_symbol: u32,
}

#[derive(Clone)]
struct IdentifierReferenceInfo {
    span: Span,
    name: String,
    symbol: Option<u32>,
}

struct ExactDexAccountTool<'a> {
    reference_symbols: &'a HashMap<u32, u32>,
    zod_symbols: &'a HashSet<u32>,
    context_symbol: u32,
    name_symbol: u32,
    schema_symbol: u32,
    found: bool,
}
impl<'a> Visit<'a> for ExactDexAccountTool<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        let matches = (|| {
            let Expression::StaticMemberExpression(callee) = &call.callee else {
                return false;
            };
            let Some(context) = ident(&callee.object) else {
                return false;
            };
            if callee.property.name != "accountTool"
                || reference_symbol(context, self.reference_symbols) != Some(self.context_symbol)
            {
                return false;
            }
            let Some(Argument::Identifier(name)) = call.arguments.first() else {
                return false;
            };
            if reference_symbol(name, self.reference_symbols) != Some(self.name_symbol) {
                return false;
            }
            let Some(Argument::ObjectExpression(options)) = call.arguments.get(1) else {
                return false;
            };
            let Some(Expression::CallExpression(schema_call)) =
                property(options, "inputSchema").map(|property| &property.value)
            else {
                return false;
            };
            let Expression::StaticMemberExpression(schema_callee) = &schema_call.callee else {
                return false;
            };
            let Some(zod) = ident(&schema_callee.object) else {
                return false;
            };
            let Some(Argument::Identifier(schema)) = schema_call.arguments.first() else {
                return false;
            };
            schema_call.arguments.len() == 1
                && schema_callee.property.name == "object"
                && reference_symbol(zod, self.reference_symbols)
                    .is_some_and(|symbol| self.zod_symbols.contains(&symbol))
                && reference_symbol(schema, self.reference_symbols) == Some(self.schema_symbol)
        })();
        self.found |= matches;
        walk::walk_call_expression(self, call);
    }
}

struct Indexer {
    reference_symbols: HashMap<u32, u32>,
    symbol_spans: HashMap<u32, Span>,
    registration_context_types: HashSet<u32>,
    zod_symbols: HashSet<u32>,
    app_factory_symbols: HashSet<u32>,
    trusted_contexts: HashSet<u32>,
    dex_bindings: HashSet<u32>,
    static_members: BTreeMap<(u32, String), String>,
    casb_arrays: HashMap<u32, Vec<CasbDefinition>>,
    casb_callbacks: Vec<CasbCallback>,
    identifier_references: Vec<IdentifierReferenceInfo>,
    binding_metadata: HashMap<u32, BindingMetadata>,
    metadata_conflict: Option<String>,
}
impl Indexer {
    fn dex_helper_matches<'a>(&self, init: &Expression<'a>) -> bool {
        let params = match init {
            Expression::ArrowFunctionExpression(function) => &function.params,
            Expression::FunctionExpression(function) => &function.params,
            _ => return false,
        };
        let Some(parameter) = params.items.first() else {
            return false;
        };
        let Some(context_symbol) = object_binding_symbol(&parameter.pattern, "context") else {
            return false;
        };
        let Some(name_symbol) = object_binding_symbol(&parameter.pattern, "name") else {
            return false;
        };
        let Some(schema_symbol) = object_binding_symbol(&parameter.pattern, "schema") else {
            return false;
        };
        let mut visitor = ExactDexAccountTool {
            reference_symbols: &self.reference_symbols,
            zod_symbols: &self.zod_symbols,
            context_symbol,
            name_symbol,
            schema_symbol,
            found: false,
        };
        visitor.visit_expression(init);
        visitor.found
    }

    fn index_declarator<'a>(&mut self, declarator: &VariableDeclarator<'a>) {
        let Some(symbol) = binding_symbol(&declarator.id) else {
            return;
        };
        let Some(init) = declarator.init.as_ref() else {
            return;
        };
        let Some(identifier) = declarator.id.get_binding_identifier() else {
            return;
        };
        let Ok(name_len) = u32::try_from(identifier.name.len()) else {
            self.metadata_conflict = Some(format!(
                "declaration name is too long for span metadata: {}",
                identifier.name
            ));
            return;
        };
        let Some(declaration_end) = identifier.span.start.checked_add(name_len) else {
            self.metadata_conflict = Some(format!(
                "declaration span overflow for symbol {symbol} ({})",
                identifier.name
            ));
            return;
        };
        let declaration = Span::new(identifier.span.start, declaration_end);
        self.add_metadata(
            symbol,
            BindingMetadata {
                classification: "same_file_initializer".into(),
                declaration,
                initializer: Some(init.span()),
                import_source: None,
                imported_name: None,
                import_declaration: None,
            },
        );
        if declarator
            .id
            .get_binding_identifier()
            .is_some_and(|identifier| identifier.name == "registerTool")
            && self.dex_helper_matches(init)
        {
            self.dex_bindings.insert(symbol);
        }
        if let Expression::ObjectExpression(object) = init {
            for object_property in &object.properties {
                let ObjectPropertyKind::ObjectProperty(object_property) = object_property else {
                    continue;
                };
                let Some(member) = key_name(&object_property.key) else {
                    continue;
                };
                if let Expression::StringLiteral(value) = &object_property.value {
                    self.static_members
                        .insert((symbol, member.into()), value.value.to_string());
                }
            }
        }
        let Some(identifier) = declarator.id.get_binding_identifier() else {
            return;
        };
        if identifier.name != "toolDefinitions" {
            return;
        }
        let Expression::ArrayExpression(array) = init else {
            return;
        };
        let definitions = array
            .elements
            .iter()
            .filter_map(|element| {
                let ArrayExpressionElement::ObjectExpression(object) = element else {
                    return None;
                };
                let Some(Expression::StringLiteral(name)) =
                    property(object, "name").map(|property| &property.value)
                else {
                    return None;
                };
                let params = property(object, "params")?;
                Some(CasbDefinition {
                    name: name.value.to_string(),
                    params: params.value.span(),
                })
            })
            .collect::<Vec<_>>();
        if !definitions.is_empty() {
            self.casb_arrays.insert(symbol, definitions);
        }
    }
    fn add_metadata(&mut self, symbol: u32, metadata: BindingMetadata) {
        if let Some(existing) = self.binding_metadata.get(&symbol) {
            if existing.classification != metadata.classification
                || existing.declaration != metadata.declaration
                || existing.initializer != metadata.initializer
                || existing.import_source != metadata.import_source
                || existing.imported_name != metadata.imported_name
                || existing.import_declaration != metadata.import_declaration
            {
                self.metadata_conflict = Some(format!(
                    "symbol {symbol}: {existing:?} conflicts with {metadata:?}"
                ));
            }
        } else {
            self.binding_metadata.insert(symbol, metadata);
        }
    }
    fn add_imports<'a>(&mut self, declaration: &ImportDeclaration<'a>) {
        if declaration.import_kind == ImportOrExportKind::Type {
            return;
        }
        let Some(specifiers) = &declaration.specifiers else {
            return;
        };
        for specifier in specifiers {
            if matches!(specifier, ImportDeclarationSpecifier::ImportSpecifier(specifier) if specifier.import_kind == ImportOrExportKind::Type)
            {
                continue;
            }
            let (local, classification, imported) = match specifier {
                ImportDeclarationSpecifier::ImportSpecifier(s) => {
                    (&s.local, "named_import", module_name(&s.imported))
                }
                ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                    (&s.local, "default_import", Some("default"))
                }
                ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                    (&s.local, "namespace_import", Some("*"))
                }
            };
            let Some(symbol) = local.symbol_id.get() else {
                continue;
            };
            self.add_metadata(
                symbol.index() as u32,
                BindingMetadata {
                    classification: classification.into(),
                    declaration: local.span,
                    initializer: None,
                    import_source: Some(declaration.source.value.to_string()),
                    imported_name: imported.map(str::to_owned),
                    import_declaration: Some(declaration.span),
                },
            );
        }
    }
}
impl<'a> Visit<'a> for Indexer {
    fn visit_import_declaration(&mut self, declaration: &ImportDeclaration<'a>) {
        self.add_imports(declaration);
        let registration_context = matches!(
            declaration.source.value.as_str(),
            "@repo/mcp-common/src/registration-context" | "../registration-context"
        );
        let zod = declaration.source.value == "zod";
        let app_factory = declaration.source.value == "@repo/mcp-common/src/mcp-app";
        if registration_context || zod || app_factory {
            for specifier in declaration.specifiers.iter().flatten() {
                let ImportDeclarationSpecifier::ImportSpecifier(specifier) = specifier else {
                    continue;
                };
                let Some(symbol) = specifier.local.symbol_id.get() else {
                    continue;
                };
                let symbol = symbol.index() as u32;
                if registration_context
                    && module_name(&specifier.imported) == Some("McpRegistrationContext")
                {
                    self.registration_context_types.insert(symbol);
                }
                if zod && module_name(&specifier.imported) == Some("z") {
                    self.zod_symbols.insert(symbol);
                }
                if app_factory && module_name(&specifier.imported) == Some("createPublicMcpApp") {
                    self.app_factory_symbols.insert(symbol);
                }
            }
        }
        walk::walk_import_declaration(self, declaration);
    }

    fn visit_formal_parameter(&mut self, parameter: &FormalParameter<'a>) {
        let Some(context_symbol) = binding_symbol(&parameter.pattern) else {
            walk::walk_formal_parameter(self, parameter);
            return;
        };
        let trusted = parameter
            .pattern
            .type_annotation
            .as_ref()
            .and_then(|annotation| match &annotation.type_annotation {
                TSType::TSTypeReference(reference) => match &reference.type_name {
                    TSTypeName::IdentifierReference(identifier) => {
                        reference_symbol(identifier, &self.reference_symbols)
                    }
                    _ => None,
                },
                _ => None,
            })
            .is_some_and(|symbol| self.registration_context_types.contains(&symbol));
        if trusted {
            self.trusted_contexts.insert(context_symbol);
        }
        walk::walk_formal_parameter(self, parameter);
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        self.index_declarator(declarator);
        walk::walk_variable_declarator(self, declarator);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Expression::Identifier(callee) = &call.callee {
            if reference_symbol(callee, &self.reference_symbols)
                .is_some_and(|symbol| self.app_factory_symbols.contains(&symbol))
            {
                if let Some(Argument::ObjectExpression(options)) = call.arguments.first() {
                    if let Some(Expression::FunctionExpression(register)) =
                        property(options, "register").map(|property| &property.value)
                    {
                        if let Some(symbol) = register
                            .params
                            .items
                            .first()
                            .and_then(|parameter| binding_symbol(&parameter.pattern))
                        {
                            self.trusted_contexts.insert(symbol);
                        }
                    }
                }
            }
        }
        let callback = (|| {
            let Expression::StaticMemberExpression(callee) = &call.callee else {
                return None;
            };
            let tool_definitions = ident(&callee.object)?;
            if callee.property.name != "forEach" {
                return None;
            }
            let definitions_symbol = reference_symbol(tool_definitions, &self.reference_symbols)?;
            if !self.casb_arrays.contains_key(&definitions_symbol) {
                return None;
            }
            let Some(Argument::ArrowFunctionExpression(function)) = call.arguments.first() else {
                return None;
            };
            let parameter = function.params.items.first()?;
            Some(CasbCallback {
                registration_spans: function
                    .body
                    .statements
                    .iter()
                    .filter_map(|statement| match statement {
                        Statement::ExpressionStatement(statement) => match &statement.expression {
                            Expression::CallExpression(call) => Some(call.span),
                            _ => None,
                        },
                        _ => None,
                    })
                    .collect(),
                definitions_symbol,
                name_symbol: object_binding_symbol(&parameter.pattern, "name")?,
                params_symbol: object_binding_symbol(&parameter.pattern, "params")?,
            })
        })();
        if let Some(callback) = callback {
            self.casb_callbacks.push(callback);
        }
        walk::walk_call_expression(self, call);
    }
}

struct Collector<'a> {
    source: &'a str,
    index: Indexer,
    syntax: HashMap<(u32, u32), SyntaxInfo>,
    records: Vec<Record>,
    blob: &'a str,
    file: &'a str,
    error: Option<String>,
}
impl<'a> Collector<'a> {
    fn context_method<'b>(&self, call: &'b CallExpression<'a>) -> Option<&'b str> {
        let Expression::StaticMemberExpression(callee) = &call.callee else {
            return None;
        };
        let context = ident(&callee.object)?;
        let method = callee.property.name.as_str();
        if !["registerTool", "accountTool", "zoneTool"].contains(&method)
            || !reference_symbol(context, &self.index.reference_symbols)
                .is_some_and(|symbol| self.index.trusted_contexts.contains(&symbol))
        {
            return None;
        }
        Some(method)
    }

    fn casb_call(&mut self, call: &CallExpression<'a>) -> bool {
        if self.context_method(call) != Some("accountTool") {
            return false;
        }
        let Some(Argument::Identifier(name)) = call.arguments.first() else {
            return false;
        };
        let Some(Argument::ObjectExpression(options)) = call.arguments.get(1) else {
            return false;
        };
        let Some(Expression::CallExpression(schema_call)) =
            property(options, "inputSchema").map(|property| &property.value)
        else {
            return false;
        };
        let Expression::StaticMemberExpression(schema_callee) = &schema_call.callee else {
            return false;
        };
        let Some(zod) = ident(&schema_callee.object) else {
            return false;
        };
        let Some(Argument::Identifier(params)) = schema_call.arguments.first() else {
            return false;
        };
        if schema_call.arguments.len() != 1
            || schema_callee.property.name != "object"
            || !reference_symbol(zod, &self.index.reference_symbols)
                .is_some_and(|symbol| self.index.zod_symbols.contains(&symbol))
        {
            return false;
        }
        let name_symbol = reference_symbol(name, &self.index.reference_symbols);
        let params_symbol = reference_symbol(params, &self.index.reference_symbols);
        let Some(callback) = self
            .index
            .casb_callbacks
            .iter()
            .find(|callback| {
                callback.registration_spans.contains(&call.span)
                    && Some(callback.name_symbol) == name_symbol
                    && Some(callback.params_symbol) == params_symbol
            })
            .cloned()
        else {
            return false;
        };
        let definitions = self
            .index
            .casb_arrays
            .get(&callback.definitions_symbol)
            .cloned()
            .unwrap_or_default();
        for definition in definitions {
            self.emit(
                call,
                "casb",
                "accountTool",
                definition.name,
                None,
                "casb_params",
                Some(definition.params),
                "inputSchema",
            );
        }
        true
    }

    fn call(&mut self, call: &CallExpression<'a>) {
        if self.casb_call(call) {
            return;
        }
        let (kind, method) = if let Some(method) = self.context_method(call) {
            ("context", method)
        } else if let Expression::Identifier(identifier) = &call.callee {
            if reference_symbol(identifier, &self.index.reference_symbols)
                .is_some_and(|symbol| self.index.dex_bindings.contains(&symbol))
                && matches!(call.arguments.first(), Some(Argument::ObjectExpression(_)))
            {
                ("dex", "registerTool")
            } else {
                return;
            }
        } else {
            return;
        };
        let Some(first) = call.arguments.first() else {
            return;
        };
        let name = match first {
            Argument::StringLiteral(name) => Some(name.value.to_string()),
            Argument::ObjectExpression(object) => {
                property(object, "name").and_then(|property| match &property.value {
                    Expression::StringLiteral(name) => Some(name.value.to_string()),
                    _ => None,
                })
            }
            Argument::StaticMemberExpression(member) => ident(&member.object)
                .and_then(|owner| reference_symbol(owner, &self.index.reference_symbols))
                .and_then(|owner| {
                    self.index
                        .static_members
                        .get(&(owner, member.property.name.to_string()))
                        .cloned()
                }),
            _ => None,
        };
        let Some(name) = name else {
            return;
        };
        if kind == "dex" {
            let Some(Argument::ObjectExpression(options)) = call.arguments.first() else {
                return;
            };
            let Some(context) =
                property(options, "context").and_then(|property| ident(&property.value))
            else {
                return;
            };
            if !reference_symbol(context, &self.index.reference_symbols)
                .is_some_and(|symbol| self.index.trusted_contexts.contains(&symbol))
            {
                return;
            }
            let Some(schema) = property(options, "schema") else {
                return;
            };
            self.emit(
                call,
                kind,
                method,
                name,
                None,
                "dex_raw_shape",
                Some(schema.value.span()),
                "schema",
            );
            return;
        }
        self.emit(
            call,
            kind,
            method,
            name,
            call.arguments.get(1),
            "input_schema",
            None,
            "inputSchema",
        );
    }
    #[allow(clippy::too_many_arguments)]
    fn emit(
        &mut self,
        call: &CallExpression<'a>,
        kind: &str,
        method: &str,
        name: String,
        options: Option<&Argument<'a>>,
        root: &str,
        schema: Option<Span>,
        key: &str,
    ) {
        let span = schema.or_else(|| match options {
            Some(Argument::ObjectExpression(object)) => {
                property(object, key).map(|property| property.value.span())
            }
            _ => None,
        });
        let conclusively_zero = span.is_none() && match options { None => true, Some(Argument::ObjectExpression(object)) => object.properties.iter().all(|property| matches!(property, ObjectPropertyKind::ObjectProperty(property) if !property.computed)), _ => false };
        let expression =
            span.map(|span| self.source[span.start as usize..span.end as usize].to_string());
        let syntax_info = span.and_then(|span| self.syntax.get(&(span.start, span.end)));
        let schema_expression_kind = syntax_info.map_or_else(
            || {
                if conclusively_zero {
                    "zero_input".into()
                } else {
                    "unknown".into()
                }
            },
            |info| info.kind.clone(),
        );
        let schema_syntax_features = syntax_info
            .map(|info| info.features.clone())
            .unwrap_or_default();
        let direct_bindings = match self.direct_bindings(span) {
            Ok(bindings) => bindings,
            Err(error) => {
                self.error.get_or_insert(error);
                return;
            }
        };
        let semantic_occurrences = syntax_info
            .map(|info| {
                info.occurrences
                    .iter()
                    .map(|occurrence| SemanticOccurrence {
                        construct: occurrence.construct.clone(),
                        signature: occurrence.signature.clone(),
                        member_chain: occurrence.member_chain.clone(),
                        file: self.file.into(),
                        blob_oid: self.blob.into(),
                        span: span_info(occurrence.span, self.source),
                        source_sha256: hex_sha(
                            &self.source
                                [occurrence.span.start as usize..occurrence.span.end as usize],
                        ),
                        dependency_node_ids: Vec::new(),
                        dependency_node_id: None,
                        capabilities: vec![name.clone()],
                        classification: occurrence.classification.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let referenced_bindings = direct_bindings
            .iter()
            .map(|binding| binding.name.clone())
            .collect();
        let schema_expression_sha256 = expression.as_ref().map(|expression| {
            let digest = Sha256::digest(expression.as_bytes());
            digest.iter().map(|byte| format!("{byte:02x}")).collect()
        });
        self.records.push(Record {
            name,
            file: self.file.into(),
            blob_oid: self.blob.into(),
            registration_span: span_info(call.span, self.source),
            schema_span: span.map(|span| span_info(span, self.source)),
            registration_kind: format!("{kind}:{method}"),
            schema_root_kind: if span.is_some() {
                root.into()
            } else if conclusively_zero {
                "implicit_zero_input".into()
            } else {
                "unsupported".into()
            },
            schema_expression_kind,
            schema_syntax_features,
            semantic_occurrences,
            schema_expression: expression,
            schema_expression_sha256,
            direct_bindings,
            referenced_bindings,
            resolution_status: "root_identified".into(),
            resolution_reason: None,
        });
    }
    fn direct_bindings(&self, schema_span: Option<Span>) -> Result<Vec<DirectBinding>, String> {
        let Some(schema_span) = schema_span else {
            return Ok(Vec::new());
        };
        let mut selected: BTreeMap<String, IdentifierReferenceInfo> = BTreeMap::new();
        for reference in &self.index.identifier_references {
            if reference.span.start < schema_span.start || reference.span.end > schema_span.end {
                continue;
            }
            if reference.symbol.is_some_and(|symbol| {
                self.index.zod_symbols.contains(&symbol)
                    || self
                        .index
                        .symbol_spans
                        .get(&symbol)
                        .is_some_and(|declaration| {
                            declaration.start >= schema_span.start
                                && declaration.end <= schema_span.end
                        })
            }) {
                continue;
            }
            let key = reference
                .symbol
                .map(|symbol| format!("s:{symbol}"))
                .unwrap_or_else(|| format!("u:{}", reference.name));
            selected
                .entry(key)
                .and_modify(|current| {
                    if reference.span.start < current.span.start {
                        *current = reference.clone();
                    }
                })
                .or_insert_with(|| reference.clone());
        }
        let mut result = selected
            .into_values()
            .map(|reference| {
                let metadata = reference
                    .symbol
                    .and_then(|symbol| self.index.binding_metadata.get(&symbol));
                let (
                    classification,
                    declaration,
                    initializer,
                    import_source,
                    imported_name,
                    import_declaration,
                ) = if let Some(metadata) = metadata {
                    (
                        metadata.classification.clone(),
                        Some(metadata.declaration),
                        metadata.initializer,
                        metadata.import_source.clone(),
                        metadata.imported_name.clone(),
                        metadata.import_declaration,
                    )
                } else if let Some(symbol) = reference.symbol {
                    (
                        "unsupported_local".into(),
                        self.index.symbol_spans.get(&symbol).copied(),
                        None,
                        None,
                        None,
                        None,
                    )
                } else {
                    ("unresolved_global".into(), None, None, None, None, None)
                };
                let initializer_expression: Option<String> = initializer
                    .map(|span| {
                        if span.start > span.end || span.end as usize > self.source.len() {
                            return Err::<String, String>(
                                "invalid initializer slice bounds".into(),
                            );
                        }
                        Ok(self.source[span.start as usize..span.end as usize].to_string())
                    })
                    .transpose()?;
                let initializer_sha256 = initializer_expression.as_ref().map(|value| {
                    Sha256::digest(value.as_bytes())
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect()
                });
                Ok(DirectBinding {
                    name: reference.name,
                    classification,
                    first_use: span_info(reference.span, self.source),
                    declaration: declaration.map(|span| span_info(span, self.source)),
                    initializer_expression,
                    initializer_span: initializer.map(|span| span_info(span, self.source)),
                    initializer_sha256,
                    import_source,
                    imported_name,
                    import_declaration: import_declaration.map(|span| span_info(span, self.source)),
                    target_status: None,
                    target_file: None,
                    target_export_name: None,
                    target_blob_oid: None,
                    target_declaration: None,
                    target_initializer_expression: None,
                    target_initializer_span: None,
                    target_initializer_sha256: None,
                    dependency_root_id: None,
                    dependency_closure_ids: Vec::new(),
                    dependency_resolution_chains: Vec::new(),
                    dependency_max_depth: None,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        result.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then(a.first_use.start_byte.cmp(&b.first_use.start_byte))
        });
        Ok(result)
    }
}
impl<'a> Visit<'a> for Collector<'a> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        self.call(call);
        walk::walk_call_expression(self, call);
    }
}

struct ReferenceCollector<'a> {
    reference_symbols: &'a HashMap<u32, u32>,
    scoping: &'a Scoping,
    references: Vec<IdentifierReferenceInfo>,
}
impl<'a> Visit<'a> for ReferenceCollector<'_> {
    fn visit_identifier_reference(&mut self, identifier: &IdentifierReference<'a>) {
        let Some(reference_id) = identifier.reference_id.get() else {
            return;
        };
        let flags = self.scoping.get_reference(reference_id).flags();
        if !flags.is_value() || flags.is_type() || flags.is_value_as_type() {
            return;
        }
        self.references.push(IdentifierReferenceInfo {
            span: identifier.span,
            name: identifier.name.to_string(),
            symbol: reference_symbol(identifier, self.reference_symbols),
        });
    }
}

pub fn parse_file(file: &str, source: &str, blob_oid: &str) -> Result<Vec<Record>, String> {
    let allocator = Allocator::default();
    let parsed = Parser::new(
        &allocator,
        source,
        SourceType::default()
            .with_typescript(true)
            .with_module(true),
    )
    .parse();
    if parsed.panicked || !parsed.errors.is_empty() {
        return Err(format!(
            "parser diagnostics in {file}: {}",
            parsed.errors.len()
        ));
    }
    let semantic_return = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(&parsed.program);
    if !semantic_return.errors.is_empty() {
        return Err(format!(
            "semantic diagnostics in {file}: {}",
            semantic_return.errors.len()
        ));
    }
    let semantic = semantic_return.semantic;
    let mut reference_symbols = HashMap::new();
    let mut symbol_spans = HashMap::new();
    for symbol in semantic.scoping().symbol_ids() {
        let symbol_index = symbol.index() as u32;
        symbol_spans.insert(symbol_index, semantic.scoping().symbol_span(symbol));
        for reference in semantic.scoping().get_resolved_reference_ids(symbol) {
            reference_symbols.insert(reference.index() as u32, symbol_index);
        }
    }
    let identifier_references = {
        let mut references = ReferenceCollector {
            reference_symbols: &reference_symbols,
            scoping: semantic.scoping(),
            references: Vec::new(),
        };
        references.visit_program(&parsed.program);
        references.references
    };
    let mut index = Indexer {
        reference_symbols,
        app_factory_symbols: HashSet::new(),
        symbol_spans,
        registration_context_types: HashSet::new(),
        zod_symbols: HashSet::new(),
        trusted_contexts: HashSet::new(),
        dex_bindings: HashSet::new(),
        static_members: BTreeMap::new(),
        casb_arrays: HashMap::new(),
        casb_callbacks: Vec::new(),
        identifier_references,
        binding_metadata: HashMap::new(),
        metadata_conflict: None,
    };
    index.visit_program(&parsed.program);
    if let Some(conflict) = index.metadata_conflict.as_ref() {
        return Err(format!(
            "conflicting binding metadata in {file}: {conflict}"
        ));
    }
    let zod_symbols = index.zod_symbols.clone();
    let reference_symbols = index.reference_symbols.clone();
    let mut syntax_indexer = SyntaxIndexer {
        zod_symbols: &zod_symbols,
        reference_symbols: &reference_symbols,
        syntax: HashMap::new(),
    };
    syntax_indexer.visit_program(&parsed.program);
    let mut collector = Collector {
        source,
        index,
        syntax: syntax_indexer.syntax,
        records: Vec::new(),
        blob: blob_oid,
        file,
        error: None,
    };
    collector.visit_program(&parsed.program);
    if let Some(error) = collector.error {
        return Err(format!("binding provenance error in {file}: {error}"));
    }
    Ok(collector.records)
}
fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    Ok(output.stdout)
}
fn validate_manifest_provenance(
    records: &[Record],
    registry: &[SemanticOccurrenceRegistryEntry],
    nodes: &[DependencyNode],
    sources: &BTreeMap<String, String>,
) -> Result<(), String> {
    let ids = nodes
        .iter()
        .map(|node| node.id.as_str())
        .collect::<BTreeSet<_>>();
    if ids.len() != nodes.len() {
        return Err("duplicate dependency node identity".into());
    }
    let owner = |file: &str, span: &SpanInfo| {
        nodes
            .iter()
            .filter(|node| {
                node.file == file
                    && node.value_span.start_byte <= span.start_byte
                    && node.value_span.end_byte >= span.end_byte
            })
            .min_by_key(|node| node.value_span.end_byte - node.value_span.start_byte)
    };
    let mut identities = BTreeSet::new();
    for entry in registry {
        let key = format!(
            "{}:{}:{}:{}:{}",
            entry.file,
            entry.span.start_byte,
            entry.span.end_byte,
            entry.construct,
            entry.dependency_node_id.as_deref().unwrap_or("")
        );
        if !identities.insert(key.clone()) {
            return Err("duplicate semantic occurrence registry identity".into());
        }
        let source = sources
            .get(&entry.file)
            .ok_or_else(|| format!("missing source for {}", entry.file))?;
        let span = entry.span.start_byte as usize..entry.span.end_byte as usize;
        if span.end > source.len() || hex_sha(&source[span.clone()]) != entry.source_sha256 {
            return Err(format!(
                "occurrence source integrity failure in {}",
                entry.file
            ));
        }
        if let Some(expected_owner) = entry.dependency_node_id.as_deref() {
            let actual = owner(&entry.file, &entry.span)
                .ok_or_else(|| format!("occurrence has no owner in {}", entry.file))?;
            if Some(actual.id.as_str()) != Some(expected_owner) || !ids.contains(actual.id.as_str())
            {
                return Err(format!(
                    "occurrence owner mismatch in {}: expected {}, actual {}",
                    entry.file, expected_owner, actual.id
                ));
            }
        }
        let expected = if let Some(node_id) = entry.dependency_node_id.as_deref() {
            records
                .iter()
                .filter(|record| {
                    record.direct_bindings.iter().any(|binding| {
                        binding
                            .dependency_closure_ids
                            .iter()
                            .any(|id| id == node_id)
                    })
                })
                .map(|record| record.name.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        } else {
            records
                .iter()
                .filter(|record| {
                    record.semantic_occurrences.iter().any(|occurrence| {
                        occurrence.file == entry.file
                            && occurrence.span == entry.span
                            && occurrence.construct == entry.construct
                            && occurrence.dependency_node_id.is_none()
                    })
                })
                .map(|record| record.name.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        };
        if entry.dependency_node_id.is_some() && expected != entry.capabilities {
            return Err(format!("capability union mismatch for {key}"));
        }
    }
    for node in nodes {
        let source = sources
            .get(&node.file)
            .ok_or_else(|| format!("missing node source {}", node.file))?;
        let span = node.value_span.start_byte as usize..node.value_span.end_byte as usize;
        if span.end > source.len() || hex_sha(&source[span]) != node.value_sha256 {
            return Err(format!("dependency value hash mismatch for {}", node.id));
        }
    }
    for record in records {
        for occurrence in &record.semantic_occurrences {
            let source = sources
                .get(&occurrence.file)
                .ok_or_else(|| format!("missing source for {}", occurrence.file))?;
            let span = occurrence.span.start_byte as usize..occurrence.span.end_byte as usize;
            if span.end > source.len() || hex_sha(&source[span]) != occurrence.source_sha256 {
                return Err(format!(
                    "record occurrence hash mismatch for {}",
                    record.name
                ));
            }
            if occurrence
                .dependency_node_ids
                .iter()
                .any(|id| !ids.contains(id.as_str()))
            {
                return Err(format!("unknown closure node in {}", record.name));
            }
        }
    }
    Ok(())
}
pub fn run(root: &Path) -> Result<Census, String> {
    let head = String::from_utf8(git(root, &["rev-parse", "HEAD"])?)
        .map_err(|_| "invalid HEAD output")?
        .trim()
        .to_string();
    if head != COMMIT {
        return Err(format!(
            "pinned checkout HEAD mismatch: expected {COMMIT}, got {head}"
        ));
    }
    let tree = String::from_utf8(git(root, &["rev-parse", "HEAD^{tree}"])?)
        .map_err(|_| "invalid tree oid")?
        .trim()
        .to_string();
    if tree != TREE {
        return Err(format!("pinned tree mismatch: expected {TREE}, got {tree}"));
    }
    let raw = git(root, &["ls-tree", "-r", "-z", COMMIT])?;
    let mut tracked = BTreeMap::new();
    let mut records = Vec::new();
    let mut files = 0;
    let mut source_cache = BTreeMap::new();
    for entry in raw
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let tab = entry
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or("malformed ls-tree entry")?;
        let meta = std::str::from_utf8(&entry[..tab]).map_err(|_| "invalid ls-tree metadata")?;
        let path = std::str::from_utf8(&entry[tab + 1..]).map_err(|_| "invalid path UTF-8")?;
        let mut fields = meta.split_whitespace();
        let mode = fields.next().ok_or("missing tree mode")?;
        let kind = fields.next().ok_or("missing tree kind")?;
        let oid = fields.next().ok_or("missing blob oid")?;
        if fields.next().is_some() {
            return Err(format!("unexpected ls-tree metadata: {meta}"));
        }
        if mode == "100644"
            && kind == "blob"
            && tracked.insert(path.to_string(), oid.to_string()).is_some()
        {
            return Err(format!("duplicate pinned tree path: {path}"));
        }
        let in_scope = path
            .strip_prefix("apps/")
            .and_then(|path| path.split_once('/'))
            .map(|(_, path)| path.starts_with("src/") || path.starts_with("server/"))
            .unwrap_or_else(|| path.starts_with("packages/mcp-common/src/"));
        if !in_scope || !path.ends_with(".ts") || path.ends_with(".spec.ts") {
            continue;
        }
        if mode != "100644" || kind != "blob" {
            return Err(format!("registration source is not a regular blob: {path}"));
        }
        let blob = git(root, &["cat-file", "blob", oid])?;
        if blob.len() > MAX_BLOB {
            return Err(format!("blob exceeds bound: {path}"));
        }
        let source =
            std::str::from_utf8(&blob).map_err(|_| format!("invalid UTF-8 blob: {path}"))?;
        source_cache.insert(path.to_string(), source.to_string());
        records.extend(parse_file(path, source, oid)?);
        files += 1;
    }
    if files != 114 {
        return Err(format!(
            "source file count mismatch: expected 114, got {files}"
        ));
    }
    // Unknown schema shapes remain census-visible; only unsupported AST forms fail closed.
    let target_status_counts = resolve_named_imports(root, &tracked, &mut records)?;
    let direct_binding_count = records
        .iter()
        .map(|record| record.direct_bindings.len())
        .sum::<usize>();
    if target_status_counts.values().sum::<usize>() != direct_binding_count
        || records.iter().any(|record| {
            record
                .direct_bindings
                .iter()
                .any(|binding| binding.target_status.is_none())
        })
    {
        return Err("incomplete direct binding target provenance".into());
    }
    let (dependency_nodes, dependency_boundaries) =
        resolve_dependency_closures(root, &tracked, &mut records)?;
    if records.iter().any(|record| {
        record.direct_bindings.iter().any(|binding| {
            binding.dependency_root_id.is_none()
                || binding.dependency_closure_ids.is_empty()
                || binding.dependency_max_depth.is_none()
                || binding.dependency_resolution_chains.is_empty()
        })
    }) {
        return Err("incomplete recursive dependency closure provenance".into());
    }
    let mut dependency_sources = source_cache;
    for node in &dependency_nodes {
        let blob = git(root, &["cat-file", "blob", &node.blob_oid])?;
        dependency_sources.entry(node.file.clone()).or_insert(
            String::from_utf8(blob)
                .map_err(|_| format!("invalid dependency blob: {}", node.file))?,
        );
    }
    for record in &mut records {
        let dependency_node_ids = record
            .direct_bindings
            .iter()
            .flat_map(|binding| binding.dependency_closure_ids.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        for occurrence in &mut record.semantic_occurrences {
            occurrence.dependency_node_ids = dependency_node_ids.clone();
        }
    }
    let mut node_capabilities: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for record in &records {
        for binding in &record.direct_bindings {
            for id in &binding.dependency_closure_ids {
                node_capabilities
                    .entry(id.clone())
                    .or_default()
                    .insert(record.name.clone());
            }
        }
    }
    let mut semantic_occurrence_registry = Vec::new();
    for node in &dependency_nodes {
        let source = dependency_sources
            .get(&node.file)
            .ok_or_else(|| format!("missing dependency source: {}", node.file))?;
        for occurrence in surveyed_syntax(source)? {
            semantic_occurrence_registry.push(SemanticOccurrenceRegistryEntry {
                construct: occurrence.construct,
                signature: occurrence.signature,
                member_chain: occurrence.member_chain,
                file: node.file.clone(),
                blob_oid: node.blob_oid.clone(),
                span: span_info(occurrence.span, source),
                source_sha256: hex_sha(
                    &source[occurrence.span.start as usize..occurrence.span.end as usize],
                ),
                dependency_node_id: Some(node.id.clone()),
                capabilities: node_capabilities
                    .get(&node.id)
                    .into_iter()
                    .flatten()
                    .cloned()
                    .collect(),
                classification: occurrence.classification,
            });
        }
    }
    let owner_for = |file: &str, span: &SpanInfo| -> Option<String> {
        dependency_nodes
            .iter()
            .filter(|node| {
                node.file == file
                    && node.value_span.start_byte <= span.start_byte
                    && node.value_span.end_byte >= span.end_byte
            })
            .min_by_key(|node| node.value_span.end_byte - node.value_span.start_byte)
            .map(|node| node.id.clone())
    };
    let mut registry: BTreeMap<String, SemanticOccurrenceRegistryEntry> =
        semantic_occurrence_registry
            .into_iter()
            .fold(BTreeMap::new(), |mut registry, entry| {
                let key = format!(
                    "{}:{}:{}:{}",
                    entry.file, entry.span.start_byte, entry.span.end_byte, entry.construct
                );
                let replace = registry
                    .get(&key)
                    .map(|current| {
                        let current_len = current
                            .dependency_node_id
                            .as_ref()
                            .and_then(|id| dependency_nodes.iter().find(|node| &node.id == id))
                            .map(|node| node.value_span.end_byte - node.value_span.start_byte);
                        let entry_len = entry
                            .dependency_node_id
                            .as_ref()
                            .and_then(|id| dependency_nodes.iter().find(|node| &node.id == id))
                            .map(|node| node.value_span.end_byte - node.value_span.start_byte);
                        entry_len < current_len
                    })
                    .unwrap_or(true);
                if replace {
                    registry.insert(key, entry);
                }
                registry
            });
    for record in &mut records {
        for occurrence in &mut record.semantic_occurrences {
            let owner = owner_for(&occurrence.file, &occurrence.span);
            occurrence.dependency_node_id = owner.clone();
            occurrence.dependency_node_ids = owner.into_iter().collect();
            let key = format!(
                "{}:{}:{}:{}:{}",
                occurrence.file,
                occurrence.span.start_byte,
                occurrence.span.end_byte,
                occurrence.construct,
                occurrence.dependency_node_id.as_deref().unwrap_or("")
            );
            let entry = registry
                .entry(key)
                .or_insert_with(|| SemanticOccurrenceRegistryEntry {
                    construct: occurrence.construct.clone(),
                    signature: occurrence.signature.clone(),
                    member_chain: occurrence.member_chain.clone(),
                    file: occurrence.file.clone(),
                    blob_oid: occurrence.blob_oid.clone(),
                    span: occurrence.span.clone(),
                    source_sha256: occurrence.source_sha256.clone(),
                    dependency_node_id: occurrence.dependency_node_id.clone(),
                    capabilities: Vec::new(),
                    classification: occurrence.classification.clone(),
                });
            if !entry.capabilities.contains(&record.name) {
                entry.capabilities.push(record.name.clone());
            }
        }
    }
    let mut semantic_occurrence_registry = registry.into_values().collect::<Vec<_>>();
    for entry in &mut semantic_occurrence_registry {
        entry.capabilities.sort();
    }
    for entry in &mut semantic_occurrence_registry {
        entry.dependency_node_id = owner_for(&entry.file, &entry.span);
        entry.capabilities = entry
            .dependency_node_id
            .as_deref()
            .map(|owner| {
                records
                    .iter()
                    .filter(|record| {
                        record.direct_bindings.iter().any(|binding| {
                            binding.dependency_closure_ids.iter().any(|id| id == owner)
                        })
                    })
                    .map(|record| record.name.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect()
            })
            .unwrap_or_default();
    }
    let mut normalized = BTreeMap::new();
    for entry in semantic_occurrence_registry.drain(..) {
        let key = format!(
            "{}:{}:{}:{}:{}",
            entry.file,
            entry.span.start_byte,
            entry.span.end_byte,
            entry.construct,
            entry.dependency_node_id.as_deref().unwrap_or("")
        );
        normalized
            .entry(key)
            .and_modify(|current: &mut SemanticOccurrenceRegistryEntry| {
                current
                    .capabilities
                    .extend(entry.capabilities.iter().cloned());
                current.capabilities.sort();
                current.capabilities.dedup();
            })
            .or_insert(entry);
    }
    let mut semantic_occurrence_registry = normalized.into_values().collect::<Vec<_>>();
    let unsupported_dependency_construct_counts = semantic_occurrence_registry
        .iter()
        .filter(|entry| {
            entry.dependency_node_id.is_some()
                && entry.classification == "unsupported_for_canonical_compile"
        })
        .fold(BTreeMap::new(), |mut counts, entry| {
            *counts.entry(entry.construct.clone()).or_insert(0) += 1;
            counts
        });
    let dependency_edge_count = dependency_nodes
        .iter()
        .map(|node| node.dependencies.len())
        .sum();
    for entry in &mut semantic_occurrence_registry {
        if let Some(owner) = owner_for(&entry.file, &entry.span) {
            entry.dependency_node_id = Some(owner.clone());
            entry.capabilities = records
                .iter()
                .filter(|record| {
                    record
                        .direct_bindings
                        .iter()
                        .any(|binding| binding.dependency_closure_ids.iter().any(|id| id == &owner))
                })
                .map(|record| record.name.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
        }
    }
    validate_manifest_provenance(
        &records,
        &semantic_occurrence_registry,
        &dependency_nodes,
        &dependency_sources,
    )?;
    let dependency_resolution_chain_count = records
        .iter()
        .flat_map(|record| &record.direct_bindings)
        .map(|binding| binding.dependency_resolution_chains.len())
        .sum();
    let dependency_max_depth = records
        .iter()
        .flat_map(|record| &record.direct_bindings)
        .filter_map(|binding| binding.dependency_max_depth)
        .max()
        .unwrap_or(0);
    let distinct_dependency_value_hash_count = dependency_nodes
        .iter()
        .map(|node| node.value_sha256.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let semantic_unknown_construct_counts = semantic_occurrence_registry
        .iter()
        .filter(|entry| entry.construct == "unknown")
        .fold(BTreeMap::new(), |mut counts, entry| {
            *counts.entry(entry.construct.clone()).or_insert(0) += 1;
            counts
        });
    let semantic_unsupported_construct_counts = semantic_occurrence_registry
        .iter()
        .filter(|entry| entry.classification == "unsupported_for_canonical_compile")
        .fold(BTreeMap::new(), |mut counts, entry| {
            *counts.entry(entry.construct.clone()).or_insert(0) += 1;
            counts
        });
    let dependency_value_kind_counts =
        dependency_nodes
            .iter()
            .fold(BTreeMap::new(), |mut counts, node| {
                *counts.entry(node.value_kind.clone()).or_insert(0) += 1;
                counts
            });
    let dependency_boundary_kind_counts =
        dependency_boundaries
            .iter()
            .fold(BTreeMap::new(), |mut counts, boundary| {
                *counts.entry(boundary.classification.clone()).or_insert(0) += 1;
                counts
            });
    let catalog: serde_json::Value = serde_json::from_str(CATALOG).map_err(|e| e.to_string())?;
    let expected: BTreeSet<String> = catalog["capabilities"]
        .as_array()
        .ok_or("catalog missing capabilities")?
        .iter()
        .filter_map(|v| v["name"].as_str().map(|s| s.to_string()))
        .collect();
    let mut counts = BTreeMap::new();
    for r in &records {
        *counts.entry(r.name.clone()).or_insert(0usize) += 1
    }
    let names = counts.keys().cloned().collect::<BTreeSet<_>>();
    let duplicates = counts
        .iter()
        .filter(|(_, count)| **count > 1)
        .map(|(name, _)| name.clone())
        .collect();
    let missing = expected.difference(&names).cloned().collect();
    let extra = names.difference(&expected).cloned().collect();
    records.sort_by(|a, b| a.name.cmp(&b.name));
    let mut zod_versions = BTreeSet::new();
    for (path, oid) in &tracked {
        if !path.ends_with("package.json") {
            continue;
        }
        let text = String::from_utf8(git(root, &["cat-file", "blob", oid])?)
            .map_err(|_| format!("invalid package manifest: {path}"))?;
        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|error| format!("invalid package manifest {path}: {error}"))?;
        for section in ["dependencies", "devDependencies", "peerDependencies"] {
            if let Some(version) = json[section]["zod"].as_str() {
                zod_versions.insert(version.to_string());
            }
        }
    }
    if zod_versions.len() != 1 || !zod_versions.contains("4.4.3") {
        return Err(format!(
            "pinned manifests do not agree on exact Zod 4.4.3: {zod_versions:?}"
        ));
    }
    Ok(Census {
        version: "6".into(),
        extractor_version: EXTRACTOR_VERSION.into(),
        provenance_claim: "schema_source_provenance_only".into(),
        source_access: "pinned_git_blobs".into(),
        schema_semantics: "not_attempted".into(),
        parser: "oxc 0.75.1 typed AST".into(),
        source_commit: COMMIT.into(),
        tree_oid: tree,
        file_count: files,
        catalog_count: expected.len(),
        zod_version: Some("4.4.3".into()),
        semantic_construct_counts: semantic_occurrence_registry.iter().fold(
            BTreeMap::new(),
            |mut counts, occurrence| {
                *counts.entry(occurrence.construct.clone()).or_insert(0) += 1;
                counts
            },
        ),
        semantic_classification_counts: semantic_occurrence_registry.iter().fold(
            BTreeMap::new(),
            |mut counts, occurrence| {
                *counts.entry(occurrence.classification.clone()).or_insert(0) += 1;
                counts
            },
        ),
        semantic_unknown_construct_counts,
        semantic_unsupported_construct_counts,
        source_count: names.len(),
        duplicates,
        missing,
        extra,
        expression_kind_counts: records.iter().fold(BTreeMap::new(), |mut counts, record| {
            *counts
                .entry(record.schema_expression_kind.clone())
                .or_insert(0) += 1;
            counts
        }),
        feature_record_counts: records.iter().fold(BTreeMap::new(), |mut counts, record| {
            for feature in &record.schema_syntax_features {
                *counts.entry(feature.clone()).or_insert(0) += 1;
            }
            counts
        }),
        direct_binding_kind_counts: records.iter().fold(BTreeMap::new(), |mut counts, record| {
            for binding in &record.direct_bindings {
                *counts.entry(binding.classification.clone()).or_insert(0) += 1;
            }
            counts
        }),
        target_status_counts,
        dependency_node_count: dependency_nodes.len(),
        dependency_edge_count,
        dependency_resolution_chain_count,
        dependency_max_depth,
        distinct_dependency_value_hash_count,
        dependency_value_kind_counts,
        dependency_boundary_kind_counts,
        unsupported_dependency_construct_counts,
        semantic_occurrence_registry,
        dependency_nodes,
        dependency_boundaries,
        records,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn record<'a>(records: &'a [Record], name: &str) -> &'a Record {
        records.iter().find(|record| record.name == name).unwrap()
    }
    fn direct_binding<'a>(record: &'a Record, name: &str) -> &'a DirectBinding {
        record
            .direct_bindings
            .iter()
            .find(|binding| binding.name == name)
            .unwrap()
    }

    #[test]
    fn fixture_enforces_typed_registration_shapes() {
        let source = include_str!("../fixtures/registrations.ts");
        let records = parse_file("fixture.ts", source, "oid").unwrap();
        let actual = records
            .iter()
            .map(|record| record.name.as_str())
            .collect::<BTreeSet<_>>();
        let expected = [
            "casb_one",
            "casb_two",
            "context_direct",
            "dex_local",
            "indirect_options",
            "dynamic_expression",
            "implicit_no_schema",
            "quoted_options",
            "inline_app",
            "outside_casb",
            "same_file_ref",
            "shadowed_z",
            "spread_options",
            "static_member_name",
            "syntax_features",
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);
        assert_eq!(
            records
                .iter()
                .filter(|record| record.schema_root_kind == "casb_params")
                .count(),
            2
        );

        let dex = record(&records, "dex_local");
        assert_eq!(dex.registration_kind, "dex:registerTool");
        assert_eq!(dex.schema_root_kind, "dex_raw_shape");
        assert_eq!(dex.schema_expression.as_deref(), Some("legacySchema"));
        assert_eq!(dex.referenced_bindings, ["legacySchema"]);

        let casb = record(&records, "casb_one");
        assert_eq!(
            casb.schema_expression.as_deref(),
            Some("{ id: z.string(), ref: importedRef }")
        );
        assert_eq!(casb.referenced_bindings, ["importedRef"]);
        assert_eq!(
            record(&records, "context_direct").referenced_bindings,
            ["directSchema"]
        );

        let direct = direct_binding(record(&records, "context_direct"), "directSchema");
        assert_eq!(direct.classification, "same_file_initializer");
        assert_eq!(
            direct.initializer_expression.as_deref(),
            Some("z.object({ id: z.string(), account: accountRef })")
        );
        let initializer = direct.initializer_expression.as_ref().unwrap();
        assert_eq!(
            direct.initializer_sha256.as_deref(),
            Some(
                Sha256::digest(initializer.as_bytes())
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
                    .as_str()
            )
        );
        let direct_use =
            &source[direct.first_use.start_byte as usize..direct.first_use.end_byte as usize];
        assert_eq!(direct_use, "directSchema");

        let imported = direct_binding(record(&records, "static_member_name"), "aliasedSchema");
        assert_eq!(imported.classification, "named_import");
        assert_eq!(imported.import_source.as_deref(), Some("./schemas"));
        assert_eq!(imported.imported_name.as_deref(), Some("importedSchema"));
        assert!(imported.import_declaration.is_some());

        let syntax_bindings = &record(&records, "syntax_features").direct_bindings;
        assert_eq!(
            syntax_bindings
                .iter()
                .map(|binding| binding.name.as_str())
                .collect::<Vec<_>>(),
            [
                "ProviderParam",
                "aliasedSchema",
                "computedKey",
                "defaultSchema",
                "helperSchema",
                "makeField",
                "schemaNamespace",
                "spreadShape",
            ]
        );

        let merged = direct_binding(record(&records, "syntax_features"), "ProviderParam");
        assert_eq!(merged.classification, "same_file_initializer");
        let merged_declaration = merged.declaration.as_ref().unwrap();
        assert_eq!(merged_declaration.start_line, 81);
        assert_eq!(
            merged_declaration.start_byte as usize,
            source.find("const ProviderParam").unwrap() + 6
        );
        assert_eq!(
            &source[merged_declaration.start_byte as usize..merged_declaration.end_byte as usize],
            "ProviderParam"
        );
        assert!(
            syntax_bindings
                .iter()
                .all(|binding| binding.name != "TypeOnlyInsideSchema")
        );
        assert_eq!(
            merged.initializer_expression.as_deref(),
            Some("z.literal(\"fixture\")")
        );
        let classified = &record(&records, "syntax_features").semantic_occurrences;
        assert!(
            classified
                .iter()
                .any(
                    |occurrence| occurrence.signature.as_deref() == Some("z.string().refine()")
                        && occurrence.classification == "zod_refinement"
                )
        );
        assert!(
            classified
                .iter()
                .any(|occurrence| occurrence.signature.as_deref()
                    == Some("z.string().transform()")
                    && occurrence.classification == "zod_transform")
        );
        assert!(
            record(&records, "shadowed_z")
                .semantic_occurrences
                .iter()
                .any(|occurrence| occurrence.classification == "shadowed_foreign")
        );
        assert_eq!(
            direct_binding(record(&records, "syntax_features"), "defaultSchema").classification,
            "default_import"
        );
        assert_eq!(
            direct_binding(record(&records, "syntax_features"), "schemaNamespace").classification,
            "namespace_import"
        );
        assert_eq!(
            direct_binding(record(&records, "syntax_features"), "helperSchema").classification,
            "unsupported_local"
        );
        assert_eq!(
            direct_binding(record(&records, "syntax_features"), "computedKey").classification,
            "unresolved_global"
        );
        for record in &records {
            assert_eq!(
                record.referenced_bindings,
                record
                    .direct_bindings
                    .iter()
                    .map(|binding| binding.name.clone())
                    .collect::<Vec<_>>()
            );
        }

        let syntax = record(&records, "syntax_features");
        assert_eq!(syntax.schema_expression_kind, "zod_object_call");
        for feature in [
            "arrow_function",
            "computed_property",
            "identifier_call:makeField",
            "object_spread",
            "static_method:default",
            "static_method:optional",
            "static_method:refine",
            "zod_factory_call:z.array",
            "zod_factory_call:z.enum",
            "zod_factory_call:z.object",
        ] {
            assert!(
                syntax
                    .schema_syntax_features
                    .iter()
                    .any(|item| item == feature)
            );
        }
        let dynamic = record(&records, "dynamic_expression");
        assert_eq!(dynamic.schema_expression_kind, "unknown");
        assert!(
            dynamic
                .schema_syntax_features
                .iter()
                .any(|feature| feature == "identifier_call:makeSchema")
        );
        let shadowed_z = record(&records, "shadowed_z");
        assert_eq!(shadowed_z.schema_expression_kind, "unknown");
        assert!(
            shadowed_z
                .schema_syntax_features
                .iter()
                .all(|feature| !feature.starts_with("zod_factory_call:"))
        );
        let quoted = record(&records, "quoted_options");
        assert_eq!(quoted.schema_expression_kind, "zod_object_call");
        assert!(
            quoted
                .schema_syntax_features
                .iter()
                .all(|feature| feature != "computed_property")
        );
        for name in ["indirect_options", "spread_options"] {
            let unsupported = record(&records, name);
            assert_eq!(unsupported.schema_expression_kind, "unknown");
            assert_eq!(unsupported.schema_root_kind, "unsupported");
        }
        let zero = record(&records, "implicit_no_schema");
        assert_eq!(zero.schema_expression_kind, "zero_input");
        assert!(
            records
                .iter()
                .any(|record| record.schema_expression_kind == "unknown")
        );
        assert_eq!(zero.schema_root_kind, "implicit_zero_input");
        for record in &records {
            assert_eq!(record.blob_oid, "oid");
            if let Some(expression) = &record.schema_expression {
                let digest = Sha256::digest(expression.as_bytes());
                let expected_hash = digest
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                assert_eq!(
                    record.schema_expression_sha256.as_deref(),
                    Some(expected_hash.as_str())
                );
            } else if record.schema_expression_kind == "zero_input" {
                assert_eq!(record.schema_root_kind, "implicit_zero_input");
                assert!(record.schema_expression_sha256.is_none());
            } else {
                assert_eq!(record.schema_expression_kind, "unknown");
                assert_eq!(record.schema_root_kind, "unsupported");
                assert!(record.schema_expression_sha256.is_none());
            }
        }

        for rejected in [
            "foreign_shadowed",
            "foreign_context",
            "foreign_method",
            "foreign_static",
            "foreign_bare",
            "foreign_dex_context",
            "string_fake",
            "foreign_app",
            "foreign_import",
            "regex_fake",
            "comment_fake",
        ] {
            assert!(
                !actual.contains(rejected),
                "accepted foreign registration: {rejected}"
            );
        }
    }

    #[test]
    fn target_export_provenance_is_typed_and_non_executing() {
        let source = r#"
            import { z } from "zod";
            export type ProviderParam = string;
            export const ProviderParam: z.ZodType<ProviderParam> = z.literal("fixture");
            throw new Error("target source must never execute");
        "#;
        let exports = target_exports("target.ts", source).unwrap();
        let values = exports.get("ProviderParam").unwrap();
        assert_eq!(values.len(), 1);
        let value = &values[0];
        assert_eq!(
            &source[value.declaration.start as usize..value.declaration.end as usize],
            "ProviderParam"
        );
        assert_eq!(
            &source[value.initializer.start as usize..value.initializer.end as usize],
            "z.literal(\"fixture\")"
        );
        assert!(target_exports("bad.ts", "export const value = (").is_err());
    }

    #[test]
    fn dependency_closure_is_recursive_typed_and_non_executing() {
        let root_file = "fixtures/root.ts";
        let shared_file = "fixtures/shared.ts";
        let root_source = r#"
            import { z } from "zod";
            import { shared } from "./shared";
            import type { TypeOnly } from "./types";
            const leaf = z.string();
            function poison() {
                throw new Error("dependency source must never execute");
            }
            export const schema = z.object({
                leaf,
                shared,
                shadowed: ((z: TypeOnly) => z)(leaf),
                poison: poison(),
            });
        "#;
        let shared_source = r#"
            import z from "zod";
            export const shared = z.number();
        "#;
        let root_module = analyze_module(root_file, root_source.into(), "root-oid".into()).unwrap();
        let shared_module =
            analyze_module(shared_file, shared_source.into(), "shared-oid".into()).unwrap();
        let tracked = BTreeMap::from([(shared_file.into(), "shared-oid".into())]);
        let mut resolver = DependencyResolver {
            root: Path::new("."),
            tracked: &tracked,
            modules: HashMap::from([
                (root_file.into(), root_module),
                (shared_file.into(), shared_module),
            ]),
            nodes: BTreeMap::new(),
            boundaries: BTreeMap::new(),
            active: Vec::new(),
        };
        let symbol = resolver.exported_symbol(root_file, "schema").unwrap();
        let root = resolver.resolve_value(root_file, symbol, 0).unwrap();
        let closure = resolver.closure(&root).unwrap();
        let chains = resolver.resolution_chains(&root).unwrap();
        let depth = chains.iter().map(|chain| chain.len() - 1).max().unwrap();

        assert!(closure.iter().any(|id| id.ends_with(":leaf")));
        assert!(closure.iter().any(|id| id.ends_with(":shared")));
        assert!(closure.iter().any(|id| id.ends_with(":poison")));
        assert!(closure.iter().any(|id| id.ends_with(":zod:z")));
        assert!(closure.iter().any(|id| id.ends_with(":zod:default")));
        assert!(closure.iter().any(|id| id.ends_with(":Error")));
        assert!(closure.iter().all(|id| !id.contains("TypeOnly")));
        assert!(depth >= 2);
        for boundary in resolver.boundaries.values() {
            assert!(!boundary.file.is_empty());
            assert!(!boundary.blob_oid.is_empty());
            assert!(boundary.source_span.start_byte < boundary.source_span.end_byte);
        }
        assert!(chains.windows(2).all(|pair| pair[0] <= pair[1]));
        assert!(
            resolver
                .nodes
                .values()
                .any(|node| node.value_kind == "function_declaration")
        );
    }

    #[test]
    fn dependency_cycles_reexports_import_forms_and_depth_fail_closed() {
        let cycle_file = "fixtures/cycle.ts";
        let cycle_source = "export const a = b; const b = a;";
        let cycle_module =
            analyze_module(cycle_file, cycle_source.into(), "cycle-oid".into()).unwrap();
        let tracked = BTreeMap::new();
        let mut resolver = DependencyResolver {
            root: Path::new("."),
            tracked: &tracked,
            modules: HashMap::from([(cycle_file.into(), cycle_module)]),
            nodes: BTreeMap::new(),
            boundaries: BTreeMap::new(),
            active: Vec::new(),
        };
        let cycle = resolver.exported_symbol(cycle_file, "a").unwrap();
        assert!(resolver.resolve_value(cycle_file, cycle, 0).is_err());

        let reexport_file = "fixtures/reexport.ts";
        let reexport = analyze_module(
            reexport_file,
            "export { shared } from './shared';".into(),
            "reexport-oid".into(),
        )
        .unwrap();
        resolver.modules.insert(reexport_file.into(), reexport);
        assert!(resolver.exported_symbol(reexport_file, "shared").is_err());

        let default_file = "fixtures/default.ts";
        let default_source = "import shared from './shared'; export const schema = shared;";
        let default_module =
            analyze_module(default_file, default_source.into(), "default-oid".into()).unwrap();
        let shared_module = analyze_module(
            "fixtures/shared.ts",
            "export const shared = 1;".into(),
            "shared-oid".into(),
        )
        .unwrap();
        let tracked = BTreeMap::from([("fixtures/shared.ts".into(), "shared-oid".into())]);
        let mut resolver = DependencyResolver {
            root: Path::new("."),
            tracked: &tracked,
            modules: HashMap::from([
                (default_file.into(), default_module),
                ("fixtures/shared.ts".into(), shared_module),
            ]),
            nodes: BTreeMap::new(),
            boundaries: BTreeMap::new(),
            active: Vec::new(),
        };
        let default = resolver.exported_symbol(default_file, "schema").unwrap();
        assert!(resolver.resolve_value(default_file, default, 0).is_err());

        let mut deep_source = String::from("export const n0 = n1;\nexport const n2 = n3;\n");
        deep_source.push_str("const n1 = n2;\n");
        for index in 3..=MAX_DEPENDENCY_DEPTH + 1 {
            deep_source.push_str(&format!("const n{index} = n{};\n", index + 1));
        }
        deep_source.push_str(&format!("const n{} = 1;\n", MAX_DEPENDENCY_DEPTH + 2));
        let deep_file = "fixtures/deep.ts";
        let deep_module = analyze_module(deep_file, deep_source, "deep-oid".into()).unwrap();
        let tracked = BTreeMap::new();
        let mut resolver = DependencyResolver {
            root: Path::new("."),
            tracked: &tracked,
            modules: HashMap::from([(deep_file.into(), deep_module)]),
            nodes: BTreeMap::new(),
            boundaries: BTreeMap::new(),
            active: Vec::new(),
        };
        let cached = resolver.exported_symbol(deep_file, "n2").unwrap();
        let cached_root = resolver.resolve_value(deep_file, cached, 0).unwrap();
        assert!(resolver.resolution_chains(&cached_root).is_ok());
        let deep = resolver.exported_symbol(deep_file, "n0").unwrap();
        let deep_root = resolver.resolve_value(deep_file, deep, 0).unwrap();
        assert!(resolver.resolution_chains(&deep_root).is_err());
    }

    #[test]
    fn target_paths_are_normalized_and_bounded() {
        assert_eq!(
            target_candidates("apps/example/src/tools/tool.ts", "../types/schema").unwrap(),
            [
                "apps/example/src/types/schema.ts",
                "apps/example/src/types/schema/index.ts"
            ]
        );
        assert_eq!(
            target_candidates(
                "apps/example/src/tools/tool.ts",
                "@repo/mcp-common/src/pagination"
            )
            .unwrap(),
            [
                "packages/mcp-common/src/pagination.ts",
                "packages/mcp-common/src/pagination/index.ts"
            ]
        );
        assert!(target_candidates("tool.ts", "../../escape").is_err());
        assert!(target_candidates("tool.ts", "external-package").is_err());
    }

    #[test]
    fn parser_and_semantic_diagnostics_fail_closed() {
        assert!(parse_file("bad.ts", "registerTool(", "o").is_err());
        assert!(parse_file("bad.ts", "const duplicate = 1; const duplicate = 2;", "o").is_err());
        let invalid = vec![u8::MAX];
        assert!(std::str::from_utf8(&invalid).is_err());
    }

    #[test]
    fn git_reads_ignore_replacement_objects() {
        use std::{fs, time::SystemTime};

        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "schema-extractor-replace-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let command = |args: &[&str]| {
            let output = Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap().trim().to_string()
        };
        command(&["init", "-q"]);
        command(&["config", "user.email", "schema-extractor@example.invalid"]);
        command(&["config", "user.name", "schema-extractor"]);
        fs::write(root.join("source.ts"), "one\n").unwrap();
        command(&["add", "source.ts"]);
        command(&["commit", "-q", "-m", "one"]);
        let original = command(&["rev-parse", "HEAD"]);
        let original_tree = command(&["rev-parse", "HEAD^{tree}"]);
        fs::write(root.join("source.ts"), "two\n").unwrap();
        command(&["commit", "-q", "-am", "two"]);
        let replacement = command(&["rev-parse", "HEAD"]);
        command(&["replace", &original, &replacement]);

        let requested = format!("{original}^{{tree}}");
        let observed = String::from_utf8(git(&root, &["rev-parse", &requested]).unwrap())
            .unwrap()
            .trim()
            .to_string();
        assert_eq!(observed, original_tree);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn output_is_deterministic() {
        let s = include_str!("../fixtures/registrations.ts");
        let a = serde_json::to_vec(&parse_file("fixture.ts", s, "oid").unwrap()).unwrap();
        let b = serde_json::to_vec(&parse_file("fixture.ts", s, "oid").unwrap()).unwrap();
        assert_eq!(a, b);
    }
}
