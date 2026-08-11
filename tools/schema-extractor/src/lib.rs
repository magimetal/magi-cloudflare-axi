use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast_visit::{Visit, walk};
use oxc_index::Idx;
use oxc_parser::Parser;
use oxc_semantic::SemanticBuilder;
use oxc_span::{GetSpan, SourceType, Span};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    path::Path,
    process::Command,
};

pub const EXTRACTOR_VERSION: &str = "phase1-oxc-0.2";
pub const COMMIT: &str = "70ff690553722f731849ede6ba9ce98958395a23";
pub const TREE: &str = "1a51c6ff07170dfe3c3212c8fb96eb85d66f0b96";
pub const CATALOG: &str = include_str!("../../../capabilities/cloudflare-mcp-parity.json");
const MAX_BLOB: usize = 8 * 1024 * 1024;

#[derive(Debug, Serialize, Clone)]
pub struct SpanInfo {
    pub start_byte: u32,
    pub end_byte: u32,
    pub start_line: usize,
    pub end_line: usize,
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
    pub schema_expression: Option<String>,
    pub schema_expression_sha256: Option<String>,
    pub referenced_bindings: Vec<String>,
    pub resolution_status: String,
    pub resolution_reason: Option<String>,
}
struct SyntaxInfo {
    kind: String,
    features: Vec<String>,
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
            },
        );
        walk::walk_expression(self, expression);
    }
}
struct SyntaxCollector<'a> {
    zod_symbols: &'a HashSet<u32>,
    reference_symbols: &'a HashMap<u32, u32>,
    features: BTreeSet<String>,
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
        walk::walk_expression(self, expression);
    }
}
#[derive(Debug, Serialize)]
pub struct Census {
    pub version: String,
    pub extractor_version: String,
    pub parser: String,
    pub source_commit: String,
    pub tree_oid: String,
    pub file_count: usize,
    pub catalog_count: usize,
    pub source_count: usize,
    pub duplicates: Vec<String>,
    pub missing: Vec<String>,
    pub extra: Vec<String>,
    pub expression_kind_counts: BTreeMap<String, usize>,
    pub feature_record_counts: BTreeMap<String, usize>,
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

#[derive(Clone)]
struct CasbCallback {
    registration_spans: Vec<Span>,
    definitions_symbol: u32,
    name_symbol: u32,
    params_symbol: u32,
}

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
}
impl<'a> Visit<'a> for Indexer {
    fn visit_import_declaration(&mut self, declaration: &ImportDeclaration<'a>) {
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
        let conclusively_zero = span.is_none()
            && match options {
                None => true,
                Some(Argument::ObjectExpression(object)) => object.properties.iter().all(
                    |property| matches!(property, ObjectPropertyKind::ObjectProperty(property) if !property.computed),
                ),
                _ => false,
            };
        let expression =
            span.map(|span| self.source[span.start as usize..span.end as usize].to_string());
        let syntax_info = span.and_then(|span| self.syntax.get(&(span.start, span.end)));
        let schema_expression_kind = syntax_info.map_or_else(
            || {
                if conclusively_zero {
                    "zero_input"
                } else {
                    "unknown"
                }
                .into()
            },
            |info| info.kind.clone(),
        );
        let schema_syntax_features = syntax_info
            .map(|info| info.features.clone())
            .unwrap_or_default();
        let referenced_bindings = span
            .map(|schema_span| {
                self.index
                    .identifier_references
                    .iter()
                    .filter(|reference| {
                        reference.span.start >= schema_span.start
                            && reference.span.end <= schema_span.end
                    })
                    .filter(|reference| {
                        !reference.symbol.is_some_and(|symbol| {
                            self.index.zod_symbols.contains(&symbol)
                                || self
                                    .index
                                    .symbol_spans
                                    .get(&symbol)
                                    .is_some_and(|declaration| {
                                        declaration.start >= schema_span.start
                                            && declaration.end <= schema_span.end
                                    })
                        })
                    })
                    .map(|reference| reference.name.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect()
            })
            .unwrap_or_default();
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
            schema_expression: expression,
            schema_expression_sha256,
            referenced_bindings,
            resolution_status: "root_identified".into(),
            resolution_reason: None,
        });
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
    references: Vec<IdentifierReferenceInfo>,
}
impl<'a> Visit<'a> for ReferenceCollector<'_> {
    fn visit_identifier_reference(&mut self, identifier: &IdentifierReference<'a>) {
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
    };
    index.visit_program(&parsed.program);
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
    };
    collector.visit_program(&parsed.program);
    Ok(collector.records)
}
fn reject_unknown_expression_kinds(records: &[Record]) -> Result<(), String> {
    let unknown = records
        .iter()
        .filter(|record| record.schema_expression_kind == "unknown")
        .map(|record| record.name.as_str())
        .collect::<Vec<_>>();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "unknown schema expression kind for {}; refusing census",
            unknown.join(", ")
        ))
    }
}
fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let o = Command::new("git")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if !o.status.success() {
        return Err(String::from_utf8_lossy(&o.stderr).into_owned());
    }
    Ok(o.stdout)
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
    let raw = git(
        root,
        &[
            "ls-tree",
            "-r",
            "-z",
            COMMIT,
            "--",
            "apps",
            "packages/mcp-common/src",
        ],
    )?;
    let mut records = Vec::new();
    let mut files = 0;
    for entry in raw.split(|b| *b == 0).filter(|e| !e.is_empty()) {
        let tab = entry
            .iter()
            .position(|b| *b == b'\t')
            .ok_or("malformed ls-tree entry")?;
        let meta = std::str::from_utf8(&entry[..tab]).map_err(|_| "invalid ls-tree metadata")?;
        let path = std::str::from_utf8(&entry[tab + 1..]).map_err(|_| "invalid path utf8")?;
        let in_scope = path
            .strip_prefix("apps/")
            .and_then(|p| p.split_once('/'))
            .map(|(_, p)| p.starts_with("src/") || p.starts_with("server/"))
            .unwrap_or_else(|| path.starts_with("packages/mcp-common/src/"));
        if !in_scope || !path.ends_with(".ts") || path.ends_with(".spec.ts") {
            continue;
        }
        let oid = meta.split_whitespace().nth(2).ok_or("missing blob oid")?;
        let blob = git(root, &["cat-file", "blob", &format!("{COMMIT}:{path}")])?;
        if blob.len() > MAX_BLOB {
            return Err(format!("blob exceeds bound: {path}"));
        }
        let source =
            std::str::from_utf8(&blob).map_err(|_| format!("invalid UTF-8 blob: {path}"))?;
        records.extend(parse_file(path, source, oid)?);
        files += 1;
    }
    if files != 114 {
        return Err(format!(
            "source file count mismatch: expected 114, got {files}"
        ));
    }
    reject_unknown_expression_kinds(&records)?;
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
        .filter(|(_, n)| **n > 1)
        .map(|(n, _)| n.clone())
        .collect();
    let missing = expected.difference(&names).cloned().collect();
    let extra = names.difference(&expected).cloned().collect();
    records.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Census {
        version: "2".into(),
        extractor_version: EXTRACTOR_VERSION.into(),
        parser: "oxc 0.75.1 typed AST".into(),
        source_commit: COMMIT.into(),
        tree_oid: tree,
        file_count: files,
        catalog_count: expected.len(),
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
        records,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn record<'a>(records: &'a [Record], name: &str) -> &'a Record {
        records.iter().find(|record| record.name == name).unwrap()
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
        assert!(reject_unknown_expression_kinds(&records).is_err());
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
