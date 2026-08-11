use crate::{Census, DependencyBoundary, DependencyNode, Record, SpanInfo};
use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};
use serde::Serialize;
use serde_json::{Map, Number, Value as Json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};

const DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";
const MAX_COMPILE_DEPTH: usize = 128;
const ZOD_4_4_3_DATE_PATTERN: &str = r"^(?:(?:\d\d[2468][048]|\d\d[13579][26]|\d\d0[48]|[02468][048]00|[13579][26]00)-02-29|\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\d|30)|(?:02)-(?:0[1-9]|1\d|2[0-8])))$";
const ZOD_4_4_3_DATE_PATTERN_SHA256: &str =
    "0a8fafe805820fa581895db8bcaee01fd241adf387c727cffe6a717fbf15813f";
const ZOD_4_4_3_EMAIL_PATTERN: &str = r"^(?!\.)(?!.*\.\.)([A-Za-z0-9_'+\-\.]*)[A-Za-z0-9_+-]@([A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$";
const ZOD_4_4_3_EMAIL_PATTERN_SHA256: &str =
    "c876175166d43d28293c5706000061fe13f06506976736689df9880818f9baf0";
const ZOD_4_4_3_UUID_PATTERN: &str = r"^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$";
const ZOD_4_4_3_UUID_PATTERN_SHA256: &str =
    "9446f7a6549d079c472562296d65b0a92634b0c2977c0e47366a36edec3059d6";
const ZOD_4_4_3_DATETIME_PATTERN: &str = r"^(?:(?:\d\d[2468][048]|\d\d[13579][26]|\d\d0[48]|[02468][048]00|[13579][26]00)-02-29|\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\d|30)|(?:02)-(?:0[1-9]|1\d|2[0-8])))T(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d+)?)?Z$";
const ZOD_4_4_3_DATETIME_PATTERN_SHA256: &str =
    "d84f6c19bed761402042ff4e769267d8380287818da250dfde1f63288115c0a3";

#[derive(Debug, Serialize)]
pub struct SchemaBundle {
    pub version: String,
    pub compiler_version: String,
    pub source_access: String,
    pub execution_policy: String,
    pub source_commit: String,
    pub tree_oid: String,
    pub zod_version: Option<String>,
    pub dialect: String,
    pub semantics_scope: String,
    pub canonicalization: String,
    pub contract_hash_canonicalization: String,
    pub candidate_complete_count: usize,
    pub candidate_zero_input_count: usize,
    pub unresolved_count: usize,
    pub dependency_provenance_count: usize,
    pub dependency_provenance_sha256: String,
    pub contracts: Vec<SchemaContract>,
}

#[derive(Debug, Serialize)]
pub struct SchemaContract {
    pub capability: String,
    pub status: String,
    pub registration_kind: String,
    pub source_file: String,
    pub source_blob_oid: String,
    pub registration_span: SpanInfo,
    pub schema_span: Option<SpanInfo>,
    pub schema_expression_sha256: Option<String>,
    pub raw_input_schema: Option<Json>,
    pub raw_input_schema_sha256: Option<String>,
    pub contract_sha256: Option<String>,
    pub unknown_key_behavior: Option<String>,
    pub unknown_key_policies: Vec<UnknownKeyPolicy>,
    pub annotations: Vec<SemanticNote>,
    pub defaults: Vec<SemanticNote>,
    pub normalizations: Vec<SemanticNote>,
    pub refinements: Vec<SemanticNote>,
    pub context_overlays: Vec<ContextOverlay>,
    pub transforms: Vec<TransformContract>,
    pub dependency_provenance: Vec<DependencyProvenance>,
    pub unresolved_reasons: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct DependencyProvenance {
    pub id: String,
    pub name: String,
    pub file: String,
    pub blob_oid: String,
    pub classification: String,
    pub source_span_kind: String,
    pub source_span: SpanInfo,
    pub source_sha256: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct SemanticNote {
    pub kind: String,
    pub schema_path: String,
    pub source: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct UnknownKeyPolicy {
    pub schema_path: String,
    pub behavior: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct TransformContract {
    pub kind: String,
    pub schema_path: String,
    pub source: String,
    pub input_branch: String,
    pub runtime_validations: Vec<String>,
    pub normalized_output_schema: Json,
    pub executor: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct ContextOverlay {
    pub predicate: String,
    pub operation: String,
    pub property: String,
    pub schema: Json,
    pub provenance: String,
}

#[derive(Clone)]
struct CompiledSchema {
    schema: Json,
    optional: bool,
    default: Option<Json>,
    annotations: Vec<SemanticNote>,
    defaults: Vec<SemanticNote>,
    normalizations: Vec<SemanticNote>,
    refinements: Vec<SemanticNote>,
    transforms: Vec<TransformContract>,
    unknown_key_policies: Vec<UnknownKeyPolicy>,
    unknown_keys: Option<String>,
}
impl CompiledSchema {
    fn new(schema: Json) -> Self {
        Self {
            schema,
            optional: false,
            default: None,
            annotations: Vec::new(),
            defaults: Vec::new(),
            normalizations: Vec::new(),
            refinements: Vec::new(),
            transforms: Vec::new(),
            unknown_key_policies: Vec::new(),
            unknown_keys: None,
        }
    }

    fn merge_notes_at(&mut self, other: &Self, prefix: &str) {
        self.annotations
            .extend(prefix_notes(&other.annotations, prefix));
        self.defaults.extend(prefix_notes(&other.defaults, prefix));
        self.normalizations
            .extend(prefix_notes(&other.normalizations, prefix));
        self.refinements
            .extend(prefix_notes(&other.refinements, prefix));
        self.transforms
            .extend(prefix_transforms(&other.transforms, prefix));
        self.unknown_key_policies
            .extend(prefix_unknown_keys(&other.unknown_key_policies, prefix));
    }
}

fn prefixed_path(prefix: &str, path: &str) -> String {
    if prefix.is_empty() {
        path.into()
    } else if path.is_empty() {
        prefix.into()
    } else {
        format!("{prefix}{path}")
    }
}

fn prefix_notes(notes: &[SemanticNote], prefix: &str) -> Vec<SemanticNote> {
    notes
        .iter()
        .cloned()
        .map(|mut note| {
            note.schema_path = prefixed_path(prefix, &note.schema_path);
            note
        })
        .collect()
}

fn prefix_transforms(transforms: &[TransformContract], prefix: &str) -> Vec<TransformContract> {
    transforms
        .iter()
        .cloned()
        .map(|mut transform| {
            transform.schema_path = prefixed_path(prefix, &transform.schema_path);
            transform
        })
        .collect()
}

fn prefix_unknown_keys(policies: &[UnknownKeyPolicy], prefix: &str) -> Vec<UnknownKeyPolicy> {
    policies
        .iter()
        .cloned()
        .map(|mut policy| {
            policy.schema_path = prefixed_path(prefix, &policy.schema_path);
            policy
        })
        .collect()
}

fn pointer_segment(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

#[derive(Clone)]
struct ShapeField {
    schema: CompiledSchema,
}

enum EvalValue {
    Schema(CompiledSchema),
    Shape(BTreeMap<String, ShapeField>),
    Json(Json),
    Regex { pattern: String, flags: String },
}

struct EvalContext {
    label: String,
    dependencies: BTreeMap<String, String>,
}

struct Compiler<'a> {
    nodes: HashMap<String, &'a DependencyNode>,
    boundaries: HashMap<String, &'a DependencyBoundary>,
    zod_version: Option<&'a str>,
    cache: HashMap<String, Result<EvalOwned, String>>,
    active: Vec<String>,
}

#[derive(Clone)]
enum EvalOwned {
    Schema(CompiledSchema),
    Shape(BTreeMap<String, ShapeField>),
    Json(Json),
    Regex { pattern: String, flags: String },
}

impl EvalOwned {
    fn borrowed(self) -> EvalValue {
        match self {
            Self::Schema(value) => EvalValue::Schema(value),
            Self::Shape(value) => EvalValue::Shape(value),
            Self::Json(value) => EvalValue::Json(value),
            Self::Regex { pattern, flags } => EvalValue::Regex { pattern, flags },
        }
    }
}

impl From<EvalValue> for EvalOwned {
    fn from(value: EvalValue) -> Self {
        match value {
            EvalValue::Schema(value) => Self::Schema(value),
            EvalValue::Shape(value) => Self::Shape(value),
            EvalValue::Json(value) => Self::Json(value),
            EvalValue::Regex { pattern, flags } => Self::Regex { pattern, flags },
        }
    }
}

pub fn compile(census: &Census) -> SchemaBundle {
    let nodes = census
        .dependency_nodes
        .iter()
        .map(|node| (node.id.clone(), node))
        .collect();
    let boundaries = census
        .dependency_boundaries
        .iter()
        .map(|boundary| (boundary.id.clone(), boundary))
        .collect();
    let mut compiler = Compiler {
        zod_version: census.zod_version.as_deref(),
        nodes,
        boundaries,
        cache: HashMap::new(),
        active: Vec::new(),
    };
    let mut contracts = census
        .records
        .iter()
        .map(|record| compiler.compile_record(record))
        .collect::<Vec<_>>();
    contracts.sort_by(|a, b| a.capability.cmp(&b.capability));
    let candidate_complete_count = contracts
        .iter()
        .filter(|contract| contract.status == "candidate_complete")
        .count();
    let candidate_zero_input_count = contracts
        .iter()
        .filter(|contract| contract.status == "candidate_zero_input")
        .count();
    let unresolved_count = contracts
        .iter()
        .filter(|contract| contract.status == "unresolved")
        .count();
    let dependency_provenance_count = contracts
        .iter()
        .map(|contract| contract.dependency_provenance.len())
        .sum();
    let dependency_provenance_by_capability = contracts
        .iter()
        .map(|contract| {
            (
                contract.capability.as_str(),
                contract.dependency_provenance.as_slice(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let dependency_provenance_sha256 =
        hex_digest(&canonical_json_bytes(&dependency_provenance_by_capability));
    SchemaBundle {
        version: "2".into(),
        compiler_version: "phase1-oxc-static-0.4".into(),
        source_access: "exact_pinned_git_blobs".into(),
        execution_policy: "static_only; never import or execute upstream TypeScript, Zod modules, registrations, or handlers".into(),
        source_commit: census.source_commit.clone(),
        tree_oid: census.tree_oid.clone(),
        zod_version: census.zod_version.clone(),
        dialect: DIALECT.into(),
        semantics_scope: "pinned_registration_input_contracts; JSON Schema validates representable raw-input semantics; external runtime contracts cover WHATWG URL validation and trimming, defaults, stripping, normalizations, transforms, and request-context overlays".into(),
        canonicalization: "serde-json-lexicographic-v1".into(),
        contract_hash_canonicalization: "sha256 of compact serialized contract with contract_sha256=null".into(),
        candidate_complete_count,
        candidate_zero_input_count,
        unresolved_count,
        dependency_provenance_count,
        dependency_provenance_sha256,
        contracts,
    }
}

impl Compiler<'_> {
    fn compile_record(&mut self, record: &Record) -> SchemaContract {
        let provenance_ids = record
            .direct_bindings
            .iter()
            .flat_map(|binding| binding.dependency_closure_ids.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let dependency_provenance = match self.dependency_provenance(&provenance_ids) {
            Ok(value) => value,
            Err(error) => return unresolved(record, Vec::new(), &error),
        };
        let context_overlays = match context_overlays(record) {
            Ok(value) => value,
            Err(error) => return unresolved(record, dependency_provenance, &error),
        };
        if record.schema_root_kind == "implicit_zero_input" {
            let schema = object_schema(BTreeMap::new(), "strip");
            return contract(
                record,
                "candidate_zero_input",
                schema,
                context_overlays,
                dependency_provenance,
            );
        }
        let Some(expression) = record.schema_expression.as_deref() else {
            return unresolved(record, dependency_provenance, "schema expression is absent");
        };
        let dependencies = match root_dependencies(record) {
            Ok(value) => value,
            Err(error) => return unresolved(record, dependency_provenance, &error),
        };
        let context = EvalContext {
            label: format!("{} root", record.name),
            dependencies,
        };
        let evaluated = self.eval_source(expression, &context, 0);
        let schema = match evaluated {
            Ok(EvalValue::Schema(schema)) => schema,
            Ok(EvalValue::Shape(shape))
                if matches!(
                    record.schema_root_kind.as_str(),
                    "dex_raw_shape" | "casb_params"
                ) =>
            {
                shape_to_schema(shape, "strip")
            }
            Ok(_) => {
                return unresolved(
                    record,
                    dependency_provenance,
                    "root did not evaluate to a schema or expected raw object shape",
                );
            }
            Err(error) => return unresolved(record, dependency_provenance, &error),
        };
        contract(
            record,
            "candidate_complete",
            schema,
            context_overlays,
            dependency_provenance,
        )
    }

    fn dependency_provenance(&self, ids: &[String]) -> Result<Vec<DependencyProvenance>, String> {
        ids.iter()
            .map(|id| {
                if let Some(node) = self.nodes.get(id) {
                    return Ok(DependencyProvenance {
                        id: id.clone(),
                        name: node.name.clone(),
                        file: node.file.clone(),
                        blob_oid: node.blob_oid.clone(),
                        classification: "dependency_node".into(),
                        source_span_kind: node.value_kind.clone(),
                        source_span: node.value_span.clone(),
                        source_sha256: node.value_sha256.clone(),
                    });
                }
                let boundary = self
                    .boundaries
                    .get(id)
                    .ok_or_else(|| format!("missing dependency provenance entry {id}"))?;
                Ok(DependencyProvenance {
                    id: id.clone(),
                    name: boundary.name.clone(),
                    file: boundary.file.clone(),
                    blob_oid: boundary.blob_oid.clone(),
                    classification: boundary.classification.clone(),
                    source_span_kind: boundary.source_span_kind.clone(),
                    source_span: boundary.source_span.clone(),
                    source_sha256: boundary.source_sha256.clone(),
                })
            })
            .collect()
    }

    fn eval_node(&mut self, id: &str, depth: usize) -> Result<EvalValue, String> {
        if depth > MAX_COMPILE_DEPTH {
            return Err(format!("semantic compile depth exceeded at {id}"));
        }
        if let Some(cached) = self.cache.get(id) {
            return cached.clone().map(EvalOwned::borrowed);
        }
        if self.active.iter().any(|active| active == id) {
            return Err(format!("semantic compile cycle at {id}"));
        }
        let node = self
            .nodes
            .get(id)
            .copied()
            .ok_or_else(|| format!("missing dependency node {id}"))?;
        if node.name == "allowedSlugs" {
            let stack_id = self
                .nodes
                .values()
                .find(|candidate| candidate.name == "STACK_LIBRARIES")
                .map(|candidate| candidate.id.clone())
                .ok_or("allowedSlugs has no pinned STACK_LIBRARIES dependency")?;
            let EvalValue::Json(Json::Array(libraries)) = self.eval_node(&stack_id, depth + 1)?
            else {
                return Err("STACK_LIBRARIES is not a static JSON array".into());
            };
            let slugs = libraries
                .into_iter()
                .map(|library| {
                    library
                        .get("slug")
                        .and_then(Json::as_str)
                        .map(|slug| Json::String(slug.into()))
                        .ok_or("STACK_LIBRARIES entry has no static slug")
                })
                .collect::<Result<Vec<_>, _>>()?;
            let result = EvalOwned::Json(Json::Array(slugs));
            self.cache.insert(id.into(), Ok(result.clone()));
            return Ok(result.borrowed());
        }
        if node.value_kind != "variable_initializer" {
            return Err(format!(
                "helper function {} requires explicit static lowering",
                node.name
            ));
        }
        let dependencies = node_dependencies(node, &self.nodes)?;
        let context = EvalContext {
            label: id.into(),
            dependencies,
        };
        self.active.push(id.into());
        let result = self.eval_source(&node.value_source, &context, depth + 1);
        self.active.pop();
        let owned = result.map(EvalOwned::from);
        self.cache.insert(id.into(), owned.clone());
        owned.map(EvalOwned::borrowed)
    }

    fn eval_source(
        &mut self,
        expression: &str,
        context: &EvalContext,
        depth: usize,
    ) -> Result<EvalValue, String> {
        let source = format!("const __schema_root = ({expression});");
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
                "semantic expression parser diagnostics in {}: {}",
                context.label,
                parsed.errors.len()
            ));
        }
        let Some(Statement::VariableDeclaration(declaration)) = parsed.program.body.first() else {
            return Err(format!(
                "semantic wrapper missing declaration in {}",
                context.label
            ));
        };
        let initializer = declaration
            .declarations
            .first()
            .and_then(|declaration| declaration.init.as_ref())
            .ok_or_else(|| format!("semantic wrapper missing initializer in {}", context.label))?;
        self.eval_expression(initializer, context, depth + 1)
    }

    fn eval_expression(
        &mut self,
        expression: &Expression<'_>,
        context: &EvalContext,
        depth: usize,
    ) -> Result<EvalValue, String> {
        if depth > MAX_COMPILE_DEPTH {
            return Err(format!(
                "semantic expression depth exceeded in {}",
                context.label
            ));
        }
        match expression {
            Expression::StringLiteral(value) => {
                Ok(EvalValue::Json(Json::String(value.value.to_string())))
            }
            Expression::TemplateLiteral(template) if template.expressions.is_empty() => {
                let value = template
                    .quasis
                    .iter()
                    .map(|quasi| {
                        quasi
                            .value
                            .cooked
                            .as_ref()
                            .map(ToString::to_string)
                            .ok_or_else(|| format!("invalid template escape in {}", context.label))
                    })
                    .collect::<Result<String, _>>()?;
                Ok(EvalValue::Json(Json::String(value)))
            }
            Expression::NumericLiteral(value) => {
                let number = if value.value.fract() == 0.0
                    && value.value >= i64::MIN as f64
                    && value.value <= i64::MAX as f64
                {
                    Number::from(value.value as i64)
                } else {
                    Number::from_f64(value.value)
                        .ok_or_else(|| format!("non-finite number in {}", context.label))?
                };
                Ok(EvalValue::Json(Json::Number(number)))
            }
            Expression::BooleanLiteral(value) => Ok(EvalValue::Json(Json::Bool(value.value))),
            Expression::NullLiteral(_) => Ok(EvalValue::Json(Json::Null)),
            Expression::Identifier(identifier) => {
                let id = context
                    .dependencies
                    .get(identifier.name.as_str())
                    .ok_or_else(|| {
                        format!(
                            "unresolved identifier {} in {}",
                            identifier.name, context.label
                        )
                    })?;
                self.eval_node(id, depth + 1)
            }
            Expression::ArrayExpression(array) => self.eval_array(array, context, depth + 1),
            Expression::ObjectExpression(object) => self.eval_object(object, context, depth + 1),
            Expression::CallExpression(call) => self.eval_call(call, context, depth + 1),
            Expression::StaticMemberExpression(member) if member.property.name == "shape" => {
                let EvalValue::Schema(schema) =
                    self.eval_expression(&member.object, context, depth + 1)?
                else {
                    return Err(format!(".shape base is not a schema in {}", context.label));
                };
                schema_to_shape(schema, context)
            }
            Expression::BinaryExpression(binary)
                if binary.operator == oxc_syntax::operator::BinaryOperator::Addition =>
            {
                let left = self.eval_expression(&binary.left, context, depth + 1)?;
                let right = self.eval_expression(&binary.right, context, depth + 1)?;
                match (left, right) {
                    (EvalValue::Json(Json::String(left)), EvalValue::Json(Json::String(right))) => {
                        Ok(EvalValue::Json(Json::String(left + &right)))
                    }
                    _ => Err(format!("non-string static addition in {}", context.label)),
                }
            }
            Expression::UnaryExpression(unary)
                if unary.operator == oxc_syntax::operator::UnaryOperator::UnaryNegation =>
            {
                let EvalValue::Json(Json::Number(number)) =
                    self.eval_expression(&unary.argument, context, depth + 1)?
                else {
                    return Err(format!(
                        "unary negation is not numeric in {}",
                        context.label
                    ));
                };
                let value = number
                    .as_i64()
                    .and_then(|value| value.checked_neg())
                    .map(Number::from)
                    .or_else(|| number.as_f64().and_then(|value| Number::from_f64(-value)))
                    .ok_or_else(|| format!("numeric negation overflow in {}", context.label))?;
                Ok(EvalValue::Json(Json::Number(value)))
            }
            Expression::RegExpLiteral(regex) => Ok(EvalValue::Regex {
                pattern: regex.regex.pattern.text.to_string(),
                flags: regex.regex.flags.to_string(),
            }),
            Expression::TSAsExpression(value) => {
                self.eval_expression(&value.expression, context, depth + 1)
            }
            Expression::TSSatisfiesExpression(value) => {
                self.eval_expression(&value.expression, context, depth + 1)
            }
            Expression::TSNonNullExpression(value) => {
                self.eval_expression(&value.expression, context, depth + 1)
            }
            Expression::ParenthesizedExpression(value) => {
                self.eval_expression(&value.expression, context, depth + 1)
            }
            _ => Err(format!(
                "unsupported expression {:?} in {}",
                expression.span(),
                context.label
            )),
        }
    }

    fn eval_array(
        &mut self,
        array: &ArrayExpression<'_>,
        context: &EvalContext,
        depth: usize,
    ) -> Result<EvalValue, String> {
        let mut values = Vec::new();
        for element in &array.elements {
            if let ArrayExpressionElement::SpreadElement(spread) = element {
                let EvalValue::Json(Json::Array(items)) =
                    self.eval_expression(&spread.argument, context, depth + 1)?
                else {
                    return Err(format!(
                        "array spread is not a static array in {}",
                        context.label
                    ));
                };
                values.extend(items.into_iter().map(EvalValue::Json));
            } else {
                let expression = element
                    .as_expression()
                    .ok_or_else(|| format!("array elision is unsupported in {}", context.label))?;
                values.push(self.eval_expression(expression, context, depth + 1)?);
            }
        }
        if values
            .iter()
            .all(|value| matches!(value, EvalValue::Json(_)))
        {
            return Ok(EvalValue::Json(Json::Array(
                values
                    .into_iter()
                    .map(|value| match value {
                        EvalValue::Json(value) => value,
                        _ => unreachable!(),
                    })
                    .collect(),
            )));
        }
        if values
            .iter()
            .all(|value| matches!(value, EvalValue::Schema(_)))
        {
            return Ok(EvalValue::Json(Json::Array(
                values
                    .into_iter()
                    .map(|value| match value {
                        EvalValue::Schema(value) => value.schema,
                        _ => unreachable!(),
                    })
                    .collect(),
            )));
        }
        Err(format!("mixed static array values in {}", context.label))
    }

    fn eval_object(
        &mut self,
        object: &ObjectExpression<'_>,
        context: &EvalContext,
        depth: usize,
    ) -> Result<EvalValue, String> {
        let mut shape = BTreeMap::new();
        let mut json = BTreeMap::new();
        let mut mode: Option<&str> = None;
        for property in &object.properties {
            match property {
                ObjectPropertyKind::ObjectProperty(property) if !property.computed => {
                    let key = static_key(&property.key)
                        .ok_or_else(|| format!("unsupported object key in {}", context.label))?;
                    let value = self.eval_expression(&property.value, context, depth + 1)?;
                    match value {
                        EvalValue::Schema(schema) if mode != Some("json") => {
                            mode = Some("shape");
                            shape.insert(key, ShapeField { schema });
                        }
                        EvalValue::Json(value) if mode != Some("shape") => {
                            mode = Some("json");
                            json.insert(key, value);
                        }
                        _ => {
                            return Err(format!(
                                "mixed or unsupported object values in {}",
                                context.label
                            ));
                        }
                    }
                }
                ObjectPropertyKind::SpreadProperty(spread) => {
                    match self.eval_expression(&spread.argument, context, depth + 1)? {
                        EvalValue::Shape(fields) if mode != Some("json") => {
                            mode = Some("shape");
                            shape.extend(fields);
                        }
                        EvalValue::Json(Json::Object(values)) if mode != Some("shape") => {
                            mode = Some("json");
                            json.extend(values);
                        }
                        _ => {
                            return Err(format!(
                                "object spread is not a compatible static object in {}",
                                context.label
                            ));
                        }
                    }
                }
                _ => return Err(format!("computed object property in {}", context.label)),
            }
        }
        if mode == Some("json") {
            Ok(EvalValue::Json(Json::Object(json.into_iter().collect())))
        } else {
            Ok(EvalValue::Shape(shape))
        }
    }

    fn eval_call(
        &mut self,
        call: &CallExpression<'_>,
        context: &EvalContext,
        depth: usize,
    ) -> Result<EvalValue, String> {
        if let Expression::Identifier(helper) = &call.callee {
            if helper.name == "normalizationParam" {
                return self.eval_normalization_param(&call.arguments, context, depth + 1);
            }
            return Err(format!(
                "helper call {} requires static lowering in {}",
                helper.name, context.label
            ));
        }
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return Err(format!("dynamic helper call in {}", context.label));
        };
        let method = member.property.name.as_str();
        if matches!(&member.object, Expression::Identifier(identifier) if identifier.name == "z") {
            return self.eval_factory(method, &call.arguments, context, depth + 1);
        }
        let base = self.eval_expression(&member.object, context, depth + 1)?;
        let EvalValue::Schema(schema) = base else {
            return Err(format!(
                "method {method} base is not a schema in {}",
                context.label
            ));
        };
        self.eval_modifier(schema, method, &call.arguments, context, depth + 1)
            .map(EvalValue::Schema)
    }

    fn eval_normalization_param(
        &mut self,
        args: &[Argument<'_>],
        context: &EvalContext,
        depth: usize,
    ) -> Result<EvalValue, String> {
        const EXPECTED_HELPER_SHA256: &str =
            "af6f16a4e3994a79c5618b37afa22dae8a15cbe39a16c969969c2df0b2d5fc46";
        let helper_id = context
            .dependencies
            .get("normalizationParam")
            .ok_or_else(|| {
                format!(
                    "normalizationParam has no resolved helper in {}",
                    context.label
                )
            })?;
        let helper = self.nodes.get(helper_id).ok_or_else(|| {
            format!(
                "normalizationParam helper node missing in {}",
                context.label
            )
        })?;
        if helper.value_sha256 != EXPECTED_HELPER_SHA256 {
            return Err(format!(
                "normalizationParam helper drift in {}: {}",
                context.label, helper.value_sha256
            ));
        }
        let rules = self.json_argument(args, 0, context, depth + 1)?;
        let Json::Object(rules) = rules else {
            return Err(format!(
                "normalization rules are not an object in {}",
                context.label
            ));
        };
        let mut values = BTreeSet::new();
        let mut descriptions = Vec::new();
        for (dimension, accepted) in rules {
            let Json::Array(accepted) = accepted else {
                return Err(format!("normalization rule {dimension} is not an array"));
            };
            let accepted = accepted
                .into_iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| format!("normalization rule {dimension} is not strings"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            values.extend(accepted.iter().cloned());
            descriptions.push(format!("{dimension} accepts {}", accepted.join(" or ")));
        }
        if values.is_empty() {
            return Err("normalizationParam produced an empty enum".into());
        }
        let mut schema = CompiledSchema::new(json_object([
            ("type", Json::String("string".into())),
            (
                "enum",
                Json::Array(values.into_iter().map(Json::String).collect()),
            ),
        ]));
        schema.optional = true;
        set_keyword(
            &mut schema.schema,
            "description",
            Json::String(format!(
                "Normalization method applied to results. {}. See https://developers.cloudflare.com/radar/concepts/normalization/",
                descriptions.join("; ")
            )),
        )?;
        schema.annotations.push(SemanticNote {
            kind: "exact_static_helper_lowering".into(),
            schema_path: String::new(),
            source: format!("normalizationParam@{EXPECTED_HELPER_SHA256}"),
        });
        Ok(EvalValue::Schema(schema))
    }

    fn eval_factory(
        &mut self,
        factory: &str,
        args: &[Argument<'_>],
        context: &EvalContext,
        depth: usize,
    ) -> Result<EvalValue, String> {
        let schema = match factory {
            "string" => type_schema("string"),
            "number" => type_schema("number"),
            "boolean" => type_schema("boolean"),
            "any" | "unknown" => CompiledSchema::new(Json::Object(Map::new())),
            "ipv4" => string_format("ipv4"),
            "ipv6" => string_format("ipv6"),
            "literal" => {
                let value = self.json_argument(args, 0, context, depth + 1)?;
                CompiledSchema::new(json_object([("const", value)]))
            }
            "enum" => {
                let contextual = matches!(
                    args.first().and_then(Argument::as_expression),
                    Some(Expression::Identifier(identifier)) if identifier.name == "allowedSlugs"
                );
                let value = self.json_argument(args, 0, context, depth + 1)?;
                let Json::Array(values) = value else {
                    return Err(format!(
                        "z.enum argument is not an array in {}",
                        context.label
                    ));
                };
                if values.is_empty() || !values.iter().all(Json::is_string) {
                    return Err(format!("z.enum values invalid in {}", context.label));
                }
                let mut result = CompiledSchema::new(json_object([
                    ("type", Json::String("string".into())),
                    ("enum", Json::Array(values)),
                ]));
                if contextual {
                    result.refinements.push(SemanticNote {
                        kind: "contextual_enum_subset".into(),
                        schema_path: String::new(),
                        source: "request query parameter libs selects a comma-split, trimmed subset of pinned STACK_LIBRARIES slugs; unknown-only or absent selection falls back to all libraries".into(),
                    });
                }
                result
            }
            "array" => {
                let item = self.schema_argument(args, 0, context, depth + 1)?;
                let mut schema = CompiledSchema::new(json_object([
                    ("type", Json::String("array".into())),
                    ("items", item.schema.clone()),
                ]));
                schema.merge_notes_at(&item, "/items");
                schema
            }
            "object" => {
                let shape = if args.is_empty() {
                    BTreeMap::new()
                } else {
                    let expression = argument_expression(&args[0], context)?;
                    match self.eval_expression(expression, context, depth + 1)? {
                        EvalValue::Shape(shape) => shape,
                        _ => {
                            return Err(format!(
                                "z.object argument is not a shape in {}",
                                context.label
                            ));
                        }
                    }
                };
                shape_to_schema(shape, "strip")
            }
            "union" => {
                let expression = argument_expression(
                    args.first()
                        .ok_or_else(|| format!("z.union missing argument in {}", context.label))?,
                    context,
                )?;
                let Expression::ArrayExpression(array) = expression else {
                    return Err(format!(
                        "z.union argument is not an array in {}",
                        context.label
                    ));
                };
                let mut branches = Vec::new();
                let mut aggregate = CompiledSchema::new(Json::Null);
                for (index, element) in array.elements.iter().enumerate() {
                    let expression = element
                        .as_expression()
                        .ok_or_else(|| format!("z.union spread/elision in {}", context.label))?;
                    let EvalValue::Schema(branch) =
                        self.eval_expression(expression, context, depth + 1)?
                    else {
                        return Err(format!("z.union branch is not schema in {}", context.label));
                    };
                    branches.push(branch.schema.clone());
                    aggregate.merge_notes_at(&branch, &format!("/anyOf/{index}"));
                }
                if branches.is_empty() {
                    return Err(format!("empty z.union in {}", context.label));
                }
                aggregate.schema = json_object([("anyOf", Json::Array(branches))]);
                aggregate
            }
            "record" => {
                let value =
                    self.schema_argument(args, args.len().saturating_sub(1), context, depth + 1)?;
                let mut schema = CompiledSchema::new(json_object([
                    ("type", Json::String("object".into())),
                    ("additionalProperties", value.schema.clone()),
                ]));
                schema.unknown_keys = Some("record_values".into());
                schema.unknown_key_policies.push(UnknownKeyPolicy {
                    schema_path: String::new(),
                    behavior: "record_values".into(),
                });
                schema.merge_notes_at(&value, "/additionalProperties");
                schema
            }
            _ => {
                return Err(format!(
                    "unsupported Zod factory {factory} in {}",
                    context.label
                ));
            }
        };
        Ok(EvalValue::Schema(schema))
    }

    fn eval_modifier(
        &mut self,
        mut schema: CompiledSchema,
        method: &str,
        args: &[Argument<'_>],
        context: &EvalContext,
        depth: usize,
    ) -> Result<CompiledSchema, String> {
        match method {
            "optional" => schema.optional = true,
            "nullable" => schema.schema = nullable(schema.schema),
            "default" => {
                let value = self.json_argument(args, 0, context, depth + 1)?;
                schema.optional = true;
                schema.default = Some(value.clone());
                set_keyword(&mut schema.schema, "default", value.clone())?;
                schema.defaults.push(SemanticNote {
                    kind: "zod_default_insertion".into(),
                    schema_path: String::new(),
                    source: value.to_string(),
                });
            }
            "describe" => {
                let expression = argument_expression(
                    args.first().ok_or_else(|| {
                        format!("description missing argument in {}", context.label)
                    })?,
                    context,
                )?;
                match self.eval_expression(expression, context, depth + 1) {
                    Ok(EvalValue::Json(value)) if value.is_string() => {
                        set_keyword(&mut schema.schema, "description", value)?;
                    }
                    Ok(_) => {
                        return Err(format!("description is not a string in {}", context.label));
                    }
                    Err(error) => {
                        let template = self.dynamic_description_template(expression, context)?;
                        schema.annotations.push(SemanticNote {
                            kind: "dynamic_description_template".into(),
                            schema_path: String::new(),
                            source: format!(
                                "nowISO@8e3c6702f40743bc41c34d3cbacd72fc0511f4e9c4766b3c7110cdf2eafc8a6d; {template}; static evaluation failure: {error}"
                            ),
                        });
                    }
                }
            }
            "min" | "max" => {
                let value = self.json_argument(args, 0, context, depth + 1)?;
                let key = match schema.schema.get("type").and_then(Json::as_str) {
                    Some("string") => {
                        if method == "min" {
                            "minLength"
                        } else {
                            "maxLength"
                        }
                    }
                    Some("array") => {
                        if method == "min" {
                            "minItems"
                        } else {
                            "maxItems"
                        }
                    }
                    Some("number" | "integer") => {
                        if method == "min" {
                            "minimum"
                        } else {
                            "maximum"
                        }
                    }
                    _ => {
                        return Err(format!(
                            "{method} unsupported for schema in {}",
                            context.label
                        ));
                    }
                };
                set_keyword(&mut schema.schema, key, value)?;
            }
            "int" => set_keyword(&mut schema.schema, "type", Json::String("integer".into()))?,
            "positive" => set_keyword(
                &mut schema.schema,
                "exclusiveMinimum",
                Json::Number(0.into()),
            )?,
            "nonnegative" => set_keyword(&mut schema.schema, "minimum", Json::Number(0.into()))?,
            "url" => {
                require_zod_4_4_3(self.zod_version, "url")?;
                if !args.is_empty() {
                    return Err(format!(
                        "option-bearing Zod URL is unsupported in {}",
                        context.label
                    ));
                }
                schema.normalizations.push(SemanticNote {
                    kind: "zod_url_trim".into(),
                    schema_path: String::new(),
                    source: "Zod 4.4.3 trims input before URL validation and, with default normalize=false, returns the trimmed string; executor=external_runtime".into(),
                });
                schema.refinements.push(SemanticNote {
                    kind: "zod_url_external_runtime_validation".into(),
                    schema_path: String::new(),
                    source: "Zod 4.4.3 invokes the JavaScript WHATWG URL constructor on trimmed input; JSON Schema cannot execute this runtime-dependent validation; executor=external_runtime".into(),
                });
            }
            "uuid" | "email" | "date" | "datetime" => {
                if !args.is_empty() {
                    return Err(format!(
                        "option-bearing Zod {method} is unsupported in {}",
                        context.label
                    ));
                }
                let (pattern, expected_hash) = match method {
                    "uuid" => (ZOD_4_4_3_UUID_PATTERN, ZOD_4_4_3_UUID_PATTERN_SHA256),
                    "email" => (ZOD_4_4_3_EMAIL_PATTERN, ZOD_4_4_3_EMAIL_PATTERN_SHA256),
                    "date" => (ZOD_4_4_3_DATE_PATTERN, ZOD_4_4_3_DATE_PATTERN_SHA256),
                    "datetime" => (
                        ZOD_4_4_3_DATETIME_PATTERN,
                        ZOD_4_4_3_DATETIME_PATTERN_SHA256,
                    ),
                    _ => unreachable!(),
                };
                let pattern =
                    exact_zod_4_4_3_pattern(self.zod_version, method, pattern, expected_hash)?;
                set_keyword(&mut schema.schema, "pattern", Json::String(pattern.into()))?;
            }
            "regex" => {
                let expression = argument_expression(
                    args.first()
                        .ok_or_else(|| format!("regex missing argument in {}", context.label))?,
                    context,
                )?;
                let EvalValue::Regex { pattern, flags } =
                    self.eval_expression(expression, context, depth + 1)?
                else {
                    return Err(format!(
                        "regex argument is not literal in {}",
                        context.label
                    ));
                };
                if !flags.is_empty() {
                    return Err(format!(
                        "regex flags {flags} are not JSON Schema equivalent in {}",
                        context.label
                    ));
                }
                let pattern = if context.label.ends_with(":DateRangeParam") {
                    self.require_context_hash(
                        context,
                        "0a56a3d5d2606d0043cf309c521a397b9225cf8a2d10e4614d8b137d6d58bd82",
                    )?;
                    "^((([1-9]|[1-9][0-9]|[1-2][0-9][0-9]|3[0-5][0-9]|36[0-4])[dD]([cC][oO][nN][tT][rR][oO][lL])?)|(([1-9]|[1-4][0-9]|5[0-2])[wW]([cC][oO][nN][tT][rR][oO][lL])?))$".into()
                } else if context.label.ends_with(":Sha256FingerprintParam") {
                    self.require_context_hash(
                        context,
                        "798c6a5262451fa263e57f4ccece677c8fc1b94a0b83d4bac54dcf15ffbaa583",
                    )?;
                    "^[A-Fa-f0-9]{64}$".into()
                } else {
                    pattern
                };
                set_keyword(&mut schema.schema, "pattern", Json::String(pattern))?;
            }
            "array" => {
                let inner = schema.clone();
                schema = CompiledSchema::new(json_object([
                    ("type", Json::String("array".into())),
                    ("items", inner.schema.clone()),
                ]));
                schema.merge_notes_at(&inner, "/items");
            }
            "passthrough" => {
                set_keyword(&mut schema.schema, "additionalProperties", Json::Bool(true))?;
                schema.unknown_keys = Some("passthrough".into());
                if let Some(policy) = schema
                    .unknown_key_policies
                    .iter_mut()
                    .find(|policy| policy.schema_path.is_empty())
                {
                    policy.behavior = "passthrough".into();
                }
            }
            "toLowerCase" | "toUpperCase" => schema.normalizations.push(SemanticNote {
                kind: method.into(),
                schema_path: String::new(),
                source: format!(".{method}()"),
            }),
            "refine" | "superRefine" => {
                if context.label.ends_with(":IpParam") {
                    schema.schema = json_object([(
                        "anyOf",
                        Json::Array(vec![
                            string_format("ipv4").schema,
                            string_format("ipv6").schema,
                        ]),
                    )]);
                    schema.refinements.push(SemanticNote {
                        kind: "exact_ip_union".into(),
                        schema_path: String::new(),
                        source: "IpParam@4e34dadb1bd44300bec079f78b391ac8fab63a562fe9c126181594ba68076a3a".into(),
                    });
                } else if context.label.ends_with(":AsnArrayParam") {
                    set_keyword(
                        &mut schema.schema,
                        "not",
                        json_object([("const", Json::String("0".into()))]),
                    )?;
                    schema.refinements.push(SemanticNote {
                        kind: "exact_not_const".into(),
                        schema_path: String::new(),
                        source: "AsnArrayParam@e4eaec3f6792de08200576b5b78ec0bcca77e390a6b8e02124a9072957f5c564".into(),
                    });
                } else {
                    return Err(format!(
                        "unsupported refinement callback in {}",
                        context.label
                    ));
                }
            }
            "transform" => {
                if !context.label.ends_with(":zTimeframeRelative") {
                    return Err(format!("unsupported transform in {}", context.label));
                }
                self.require_context_hash(
                    context,
                    "ace1e9f13fcb2a03ed82f656430cd28caec0ba07fbd1058041c106f916bb6d93",
                )?;
                schema.transforms.push(TransformContract {
                    kind: "relative_timeframe_to_absolute".into(),
                    schema_path: String::new(),
                    source: "apps/workers-observability/src/types/workers-logs.types.ts:zTimeframeRelative@ace1e9f13fcb2a03ed82f656430cd28caec0ba07fbd1058041c106f916bb6d93; packages/mcp-common/src/utils.ts:parseRelativeTime@607cbd187cd68ab6ae56f3908bef94c8e44de520a6fa1750eb329a80cd5be054".into(),
                    input_branch: "object with required reference and offset strings".into(),
                    runtime_validations: vec![
                        "reference must produce a finite timestamp through JavaScript Date parsing".into(),
                        "offset removes all JavaScript regular-expression whitespace, lowercases units, then must match ^[+-](?:\\d+[smhdw])+$; numeric accumulation must remain finite".into(),
                        "computed from/to dates must remain within JavaScript Date.toISOString() representable range; otherwise transform throws".into(),
                        "from=min(reference+offset,reference) and to=max(reference+offset,reference), serialized with Date.toISOString()".into(),
                    ],
                    normalized_output_schema: json_object([
                        ("type", Json::String("object".into())),
                        (
                            "properties",
                            json_object([
                                ("from", string_format("date-time").schema),
                                ("to", string_format("date-time").schema),
                            ]),
                        ),
                        (
                            "required",
                            Json::Array(vec![Json::String("from".into()), Json::String("to".into())]),
                        ),
                        ("additionalProperties", Json::Bool(false)),
                    ]),
                    executor: "external_runtime; JSON Schema does not execute this transform".into(),
                });
            }
            _ => {
                return Err(format!(
                    "unsupported Zod modifier {method} in {}",
                    context.label
                ));
            }
        }
        Ok(schema)
    }

    fn require_context_hash(&self, context: &EvalContext, expected: &str) -> Result<(), String> {
        if cfg!(test) && context.label.starts_with("fixture:") {
            return Ok(());
        }
        let node = self
            .nodes
            .get(&context.label)
            .ok_or_else(|| format!("missing pinned semantic node for {}", context.label))?;
        if node.value_sha256 != expected {
            return Err(format!(
                "pinned semantic lowering drift in {}: expected {expected}, got {}",
                context.label, node.value_sha256
            ));
        }
        Ok(())
    }

    fn dynamic_description_template(
        &self,
        expression: &Expression<'_>,
        context: &EvalContext,
    ) -> Result<String, String> {
        let Expression::TemplateLiteral(template) = expression else {
            return Err(format!(
                "unsupported dynamic description expression in {}",
                context.label
            ));
        };
        let now_id = context.dependencies.get("nowISO").ok_or_else(|| {
            format!(
                "dynamic description has no pinned nowISO dependency in {}",
                context.label
            )
        })?;
        let now = self
            .nodes
            .get(now_id)
            .ok_or_else(|| format!("missing pinned nowISO node {now_id}"))?;
        const NOW_SHA256: &str = "8e3c6702f40743bc41c34d3cbacd72fc0511f4e9c4766b3c7110cdf2eafc8a6d";
        if now.value_sha256 != NOW_SHA256 {
            return Err(format!(
                "pinned nowISO lowering drift: expected {NOW_SHA256}, got {}",
                now.value_sha256
            ));
        }
        let mut result = String::new();
        for (index, quasi) in template.quasis.iter().enumerate() {
            result.push_str(
                quasi
                    .value
                    .cooked
                    .as_ref()
                    .ok_or_else(|| format!("invalid dynamic template escape in {}", context.label))?
                    .as_str(),
            );
            if let Some(slot) = template.expressions.get(index) {
                let Expression::CallExpression(call) = slot else {
                    return Err(format!(
                        "unsupported dynamic description slot in {}",
                        context.label
                    ));
                };
                if !call.arguments.is_empty()
                    || !matches!(&call.callee, Expression::Identifier(identifier) if identifier.name == "nowISO")
                {
                    return Err(format!(
                        "unsupported dynamic description call in {}",
                        context.label
                    ));
                }
                result.push_str("${nowISO()}");
            }
        }
        Ok(result)
    }

    fn json_argument(
        &mut self,
        args: &[Argument<'_>],
        index: usize,
        context: &EvalContext,
        depth: usize,
    ) -> Result<Json, String> {
        let argument = args
            .get(index)
            .ok_or_else(|| format!("missing argument {index} in {}", context.label))?;
        let expression = argument_expression(argument, context)?;
        match self.eval_expression(expression, context, depth + 1)? {
            EvalValue::Json(value) => Ok(value),
            _ => Err(format!(
                "argument {index} is not static JSON in {}",
                context.label
            )),
        }
    }

    fn schema_argument(
        &mut self,
        args: &[Argument<'_>],
        index: usize,
        context: &EvalContext,
        depth: usize,
    ) -> Result<CompiledSchema, String> {
        let argument = args
            .get(index)
            .ok_or_else(|| format!("missing schema argument {index} in {}", context.label))?;
        let expression = argument_expression(argument, context)?;
        match self.eval_expression(expression, context, depth + 1)? {
            EvalValue::Schema(value) => Ok(value),
            _ => Err(format!(
                "argument {index} is not a schema in {}",
                context.label
            )),
        }
    }
}

fn root_dependencies(record: &Record) -> Result<BTreeMap<String, String>, String> {
    let mut result = BTreeMap::new();
    for binding in &record.direct_bindings {
        let id = binding
            .dependency_root_id
            .as_ref()
            .ok_or_else(|| format!("binding {} has no dependency root", binding.name))?;
        insert_dependency(&mut result, &binding.name, id)?;
    }
    Ok(result)
}

fn node_dependencies(
    node: &DependencyNode,
    nodes: &HashMap<String, &DependencyNode>,
) -> Result<BTreeMap<String, String>, String> {
    let mut result = BTreeMap::new();
    for id in &node.dependencies {
        if let Some(dependency) = nodes.get(id) {
            insert_dependency(&mut result, &dependency.name, id)?;
        }
    }
    Ok(result)
}

fn insert_dependency(
    dependencies: &mut BTreeMap<String, String>,
    name: &str,
    id: &str,
) -> Result<(), String> {
    if let Some(previous) = dependencies.insert(name.into(), id.into()) {
        if previous != id {
            return Err(format!(
                "ambiguous dependency name {name}: {previous}, {id}"
            ));
        }
    }
    Ok(())
}

fn context_overlays(record: &Record) -> Result<Vec<ContextOverlay>, String> {
    let mut overlays = match record.registration_kind.as_str() {
        "context:registerTool" => Vec::new(),
        "context:accountTool" | "dex:registerTool" | "casb:accountTool" => {
            vec![ContextOverlay {
                predicate: "accountManager.requiresAccountSelection === true".into(),
                operation: "extend_optional_property".into(),
                property: "account_id".into(),
                schema: json_object([
                    ("type", Json::String("string".into())),
                    (
                        "description",
                        Json::String("The Cloudflare account ID to scope this call to. Only needed when your credentials can access multiple accounts and no cf-account-id header is configured.".into()),
                    ),
                ]),
                provenance: "packages/mcp-common/src/account-tool.ts:buildAccountTool; packages/mcp-common/src/account-manager.ts:AccountIdParam@70ff690553722f731849ede6ba9ce98958395a23".into(),
            }]
        }
        other => return Err(format!("unsupported registration kind {other}")),
    };
    if record.name == "search_dev_stack" {
        overlays.push(ContextOverlay {
            predicate: "request URL query parameter libs is comma-split and trimmed; known slugs are selected in pinned STACK_LIBRARIES order; absent, empty, or unknown-only values select all ten libraries".into(),
            operation: "restrict_enum_to_request_selected_subset".into(),
            property: "library".into(),
            schema: json_object([
                ("type", Json::String("string".into())),
                (
                    "enum",
                    Json::Array(
                        [
                            "cloudflare",
                            "cloudflare-api",
                            "cloudflare-blog",
                            "cloudflare-community",
                            "vite",
                            "vitest",
                            "astro",
                            "opennext",
                            "replicate",
                            "hono",
                        ]
                        .into_iter()
                        .map(|value| Json::String(value.into()))
                        .collect(),
                    ),
                ),
            ]),
            provenance: "apps/stack-mcp/src/tools/stack.tools.ts:registerStackTools; apps/stack-mcp/src/types/stack.types.ts:resolveLibraries@70ff690553722f731849ede6ba9ce98958395a23".into(),
        });
    }
    Ok(overlays)
}

fn contract(
    record: &Record,
    status: &str,
    schema: CompiledSchema,
    context_overlays: Vec<ContextOverlay>,
    dependency_provenance: Vec<DependencyProvenance>,
) -> SchemaContract {
    let hash = hex_digest(&canonical_json_bytes(&schema.schema));
    let mut result = SchemaContract {
        capability: record.name.clone(),
        status: status.into(),
        registration_kind: record.registration_kind.clone(),
        source_file: record.file.clone(),
        source_blob_oid: record.blob_oid.clone(),
        registration_span: record.registration_span.clone(),
        schema_span: record.schema_span.clone(),
        schema_expression_sha256: record.schema_expression_sha256.clone(),
        raw_input_schema: Some(schema.schema),
        raw_input_schema_sha256: Some(hash),
        contract_sha256: None,
        unknown_key_behavior: schema.unknown_keys.or_else(|| Some("strip".into())),
        unknown_key_policies: schema.unknown_key_policies,
        defaults: schema.defaults,
        annotations: schema.annotations,
        normalizations: schema.normalizations,
        refinements: schema.refinements,
        context_overlays,
        transforms: schema.transforms,
        dependency_provenance,
        unresolved_reasons: Vec::new(),
    };
    result.contract_sha256 = Some(hex_digest(&canonical_json_bytes(&result)));
    result
}

fn unresolved(
    record: &Record,
    dependency_provenance: Vec<DependencyProvenance>,
    reason: &str,
) -> SchemaContract {
    let mut result = SchemaContract {
        capability: record.name.clone(),
        status: "unresolved".into(),
        registration_kind: record.registration_kind.clone(),
        source_file: record.file.clone(),
        source_blob_oid: record.blob_oid.clone(),
        registration_span: record.registration_span.clone(),
        schema_span: record.schema_span.clone(),
        schema_expression_sha256: record.schema_expression_sha256.clone(),
        raw_input_schema: None,
        raw_input_schema_sha256: None,
        contract_sha256: None,
        unknown_key_behavior: None,
        unknown_key_policies: Vec::new(),
        defaults: Vec::new(),
        annotations: Vec::new(),
        normalizations: Vec::new(),
        refinements: Vec::new(),
        context_overlays: Vec::new(),
        transforms: Vec::new(),
        dependency_provenance,
        unresolved_reasons: vec![reason.into()],
    };
    result.contract_sha256 = Some(hex_digest(&canonical_json_bytes(&result)));
    result
}

fn canonical_json_bytes(value: &impl Serialize) -> Vec<u8> {
    let value = serde_json::to_value(value).expect("canonical JSON value serialization");
    let mut bytes = Vec::new();
    write_canonical_json(&value, &mut bytes);
    bytes
}

fn write_canonical_json(value: &Json, output: &mut Vec<u8>) {
    match value {
        Json::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output);
            }
            output.push(b']');
        }
        Json::Object(object) => {
            output.push(b'{');
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key).expect("canonical JSON key serialization");
                output.push(b':');
                write_canonical_json(&object[key], output);
            }
            output.push(b'}');
        }
        _ => serde_json::to_writer(output, value).expect("canonical JSON scalar serialization"),
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn require_zod_4_4_3(zod_version: Option<&str>, semantic: &str) -> Result<(), String> {
    if zod_version != Some("4.4.3") {
        return Err(format!(
            "Zod {semantic} lowering requires exact version 4.4.3, got {zod_version:?}"
        ));
    }
    Ok(())
}

fn exact_zod_4_4_3_pattern(
    zod_version: Option<&str>,
    semantic: &str,
    pattern: &'static str,
    expected_hash: &str,
) -> Result<&'static str, String> {
    require_zod_4_4_3(zod_version, semantic)?;
    let actual = hex_digest(pattern.as_bytes());
    if actual != expected_hash {
        return Err(format!(
            "Zod 4.4.3 {semantic} lowering hash drift: expected {expected_hash}, got {actual}"
        ));
    }
    Ok(pattern)
}

fn shape_to_schema(shape: BTreeMap<String, ShapeField>, unknown_keys: &str) -> CompiledSchema {
    let mut properties = Map::new();
    let mut required = Vec::new();
    let mut result = CompiledSchema::new(Json::Null);
    for (name, field) in shape {
        if !field.schema.optional {
            required.push(Json::String(name.clone()));
        }
        let path = format!("/properties/{}", pointer_segment(&name));
        result.merge_notes_at(&field.schema, &path);
        properties.insert(name, field.schema.schema);
    }
    let mut schema = Map::new();
    schema.insert("type".into(), Json::String("object".into()));
    schema.insert("properties".into(), Json::Object(properties));
    if !required.is_empty() {
        schema.insert("required".into(), Json::Array(required));
    }
    result.schema = Json::Object(schema);
    result.unknown_keys = Some(unknown_keys.into());
    result.unknown_key_policies.push(UnknownKeyPolicy {
        schema_path: String::new(),
        behavior: unknown_keys.into(),
    });
    result
}

fn object_schema(shape: BTreeMap<String, ShapeField>, unknown_keys: &str) -> CompiledSchema {
    shape_to_schema(shape, unknown_keys)
}
fn type_schema(kind: &str) -> CompiledSchema {
    CompiledSchema::new(json_object([("type", Json::String(kind.into()))]))
}

fn string_format(format: &str) -> CompiledSchema {
    CompiledSchema::new(json_object([
        ("type", Json::String("string".into())),
        ("format", Json::String(format.into())),
    ]))
}

fn schema_to_shape(schema: CompiledSchema, context: &EvalContext) -> Result<EvalValue, String> {
    let properties = schema
        .schema
        .get("properties")
        .and_then(Json::as_object)
        .ok_or_else(|| format!(".shape schema has no properties in {}", context.label))?;
    let required = schema
        .schema
        .get("required")
        .and_then(Json::as_array)
        .into_iter()
        .flatten()
        .filter_map(Json::as_str)
        .collect::<BTreeSet<_>>();
    let fields = properties
        .iter()
        .map(|(name, value)| {
            let mut field = CompiledSchema::new(value.clone());
            field.optional = !required.contains(name.as_str());
            (name.clone(), ShapeField { schema: field })
        })
        .collect();
    Ok(EvalValue::Shape(fields))
}

fn nullable(schema: Json) -> Json {
    json_object([(
        "anyOf",
        Json::Array(vec![
            schema,
            json_object([("type", Json::String("null".into()))]),
        ]),
    )])
}

fn set_keyword(schema: &mut Json, key: &str, value: Json) -> Result<(), String> {
    let object = schema
        .as_object_mut()
        .ok_or_else(|| format!("schema is not an object while setting {key}"))?;
    object.insert(key.into(), value);
    Ok(())
}

fn json_object<const N: usize>(entries: [(&str, Json); N]) -> Json {
    Json::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}

fn argument_expression<'a>(
    argument: &'a Argument<'a>,
    context: &EvalContext,
) -> Result<&'a Expression<'a>, String> {
    argument
        .as_expression()
        .ok_or_else(|| format!("spread argument unsupported in {}", context.label))
}

fn static_key(key: &PropertyKey<'_>) -> Option<String> {
    match key {
        PropertyKey::StaticIdentifier(value) => Some(value.name.to_string()),
        PropertyKey::StringLiteral(value) => Some(value.value.to_string()),
        PropertyKey::NumericLiteral(value) => Some(value.value.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_compiler() -> Compiler<'static> {
        Compiler {
            nodes: HashMap::new(),
            boundaries: HashMap::new(),
            cache: HashMap::new(),
            active: Vec::new(),
            zod_version: Some("4.4.3"),
        }
    }

    #[test]
    fn inline_zod_schema_is_lowered_without_execution() {
        let mut compiler = empty_compiler();
        let context = EvalContext {
            label: "fixture".into(),
            dependencies: BTreeMap::new(),
        };
        let EvalValue::Schema(schema) = compiler.eval_source(
            r#"z.object({ id: z.string().uuid(), count: z.number().int().min(1).optional().default(2), mode: z.enum(["a", "b"]) })"#,
            &context,
            0,
        ).unwrap() else { panic!("expected schema") };
        assert_eq!(schema.schema["type"], "object");
        assert_eq!(
            schema.schema["properties"]["id"]["pattern"],
            ZOD_4_4_3_UUID_PATTERN
        );
        assert_eq!(schema.schema["properties"]["count"]["minimum"], 1);
        assert_eq!(schema.schema["properties"]["count"]["default"], 2);
        assert_eq!(schema.schema["required"], serde_json::json!(["id", "mode"]));
        assert_eq!(schema.defaults.len(), 1);
    }

    #[test]
    fn zod_4_4_3_string_formats_preserve_exact_or_external_semantics() {
        let mut compiler = empty_compiler();
        for (source, pattern, accepted, rejected) in [
            (
                "z.string().email()",
                ZOD_4_4_3_EMAIL_PATTERN,
                vec!["user@example.com", "o'hara+tag@example.co.uk"],
                vec!["a@localhost", ".a@example.com", "a..b@example.com"],
            ),
            (
                "z.string().uuid()",
                ZOD_4_4_3_UUID_PATTERN,
                vec![
                    "550e8400-e29b-41d4-a716-446655440000",
                    "00000000-0000-0000-0000-000000000000",
                    "ffffffff-ffff-ffff-ffff-ffffffffffff",
                ],
                vec![
                    "00000000-0000-4000-0000-000000000000",
                    "550e8400-e29b-01d4-a716-446655440000",
                ],
            ),
            (
                "z.string().date()",
                ZOD_4_4_3_DATE_PATTERN,
                vec!["2000-02-29", "2020-12-31"],
                vec!["1900-02-29", "2020-04-31", "2020-1-01"],
            ),
        ] {
            let EvalValue::Schema(schema) = compiler
                .eval_source(source, &fixture_context("fixture"), 0)
                .unwrap()
            else {
                panic!("expected schema")
            };
            assert_eq!(schema.schema["pattern"], pattern);
            assert!(schema.schema.get("format").is_none());
            let validator = jsonschema::draft202012::new(&schema.schema).unwrap();
            for value in accepted {
                assert!(validator.is_valid(&Json::String(value.into())), "{value}");
            }
            for value in rejected {
                assert!(!validator.is_valid(&Json::String(value.into())), "{value}");
            }
        }

        let EvalValue::Schema(url) = compiler
            .eval_source("z.string().url()", &fixture_context("fixture"), 0)
            .unwrap()
        else {
            panic!("expected schema")
        };
        assert_eq!(url.schema, serde_json::json!({"type": "string"}));
        assert_eq!(url.normalizations.len(), 1);
        assert_eq!(url.normalizations[0].kind, "zod_url_trim");
        assert!(
            url.normalizations[0]
                .source
                .contains("default normalize=false")
        );
        assert!(url.normalizations[0].source.contains("trimmed string"));
        assert_eq!(url.refinements.len(), 1);
        assert_eq!(
            url.refinements[0].kind,
            "zod_url_external_runtime_validation"
        );
        assert!(url.refinements[0].source.contains("WHATWG URL constructor"));
        assert!(url.refinements[0].source.contains("trimmed input"));
        assert!(!url.refinements[0].source.contains("raw input"));
        for source in [
            "z.string().email({ message: 'x' })",
            "z.string().uuid({ version: 'v4' })",
            "z.string().url({ protocol: /https/ })",
            "z.string().date({ error: 'x' })",
        ] {
            assert!(
                compiler
                    .eval_source(source, &fixture_context("fixture"), 0)
                    .is_err()
            );
        }
        compiler.zod_version = Some("4.4.4");
        assert!(
            compiler
                .eval_source("z.string().url()", &fixture_context("fixture"), 0)
                .is_err()
        );
    }

    #[test]
    fn zod_4_4_3_datetime_lowering_matches_default_boundaries() {
        let mut compiler = empty_compiler();
        let EvalValue::Schema(schema) = compiler
            .eval_source("z.string().datetime()", &fixture_context("fixture"), 0)
            .unwrap()
        else {
            panic!("expected schema")
        };
        assert_eq!(
            schema.schema["pattern"],
            Json::String(ZOD_4_4_3_DATETIME_PATTERN.into())
        );
        assert!(schema.schema.get("format").is_none());
        let validator = jsonschema::draft202012::new(&schema.schema).unwrap();
        for accepted in [
            "2020-01-01T06:15Z",
            "2020-01-01T06:15:30Z",
            "2020-01-01T06:15:30.1Z",
            "2020-01-01T06:15:30.123456789Z",
            "2000-02-29T23:59:59Z",
        ] {
            assert!(
                validator.is_valid(&Json::String(accepted.into())),
                "{accepted}"
            );
        }
        for rejected in [
            "2020-01-01T06:15+02:00",
            "2020-01-01T06:15:30-07:00",
            "2020-01-01T06:15",
            "2019-02-29T06:15Z",
            "1900-02-29T06:15Z",
            "2020-04-31T06:15Z",
            "2020-01-01T24:00Z",
            "2020-01-01T06:60Z",
            "2020-01-01T06:15.1Z",
        ] {
            assert!(
                !validator.is_valid(&Json::String(rejected.into())),
                "{rejected}"
            );
        }
        assert!(
            compiler
                .eval_source(
                    "z.string().datetime({ offset: true })",
                    &fixture_context("fixture"),
                    0,
                )
                .is_err()
        );
        compiler.zod_version = Some("4.4.4");
        assert!(
            compiler
                .eval_source("z.string().datetime()", &fixture_context("fixture"), 0)
                .is_err()
        );
    }

    #[test]
    fn transforms_are_recorded_not_executed() {
        let mut compiler = empty_compiler();
        let context = EvalContext {
            label: "fixture:zTimeframeRelative".into(),
            dependencies: BTreeMap::new(),
        };
        let EvalValue::Schema(schema) = compiler
            .eval_source(
                r#"z.string().transform(() => { throw new Error("must not execute") })"#,
                &context,
                0,
            )
            .unwrap()
        else {
            panic!("expected schema")
        };
        assert_eq!(schema.schema["type"], "string");
        assert_eq!(schema.transforms.len(), 1);
    }

    #[test]
    fn unsupported_semantics_fail_closed() {
        let mut compiler = empty_compiler();
        let context = EvalContext {
            label: "fixture".into(),
            dependencies: BTreeMap::new(),
        };
        assert!(
            compiler
                .eval_source("z.coerce.number()", &context, 0)
                .is_err()
        );
        assert!(compiler.eval_source("makeSchema()", &context, 0).is_err());
    }

    fn fixture_context(label: &str) -> EvalContext {
        EvalContext {
            label: label.into(),
            dependencies: BTreeMap::new(),
        }
    }

    fn fixture_span() -> SpanInfo {
        SpanInfo {
            start_byte: 0,
            end_byte: 1,
            start_line: 1,
            end_line: 1,
        }
    }

    fn fixture_record(name: &str, registration_kind: &str) -> Record {
        Record {
            name: name.into(),
            file: "fixture.ts".into(),
            blob_oid: "fixture-oid".into(),
            registration_span: fixture_span(),
            schema_span: None,
            registration_kind: registration_kind.into(),
            schema_root_kind: "zod_object".into(),
            schema_expression_kind: "zod_object_call".into(),
            schema_syntax_features: Vec::new(),
            semantic_occurrences: Vec::new(),
            schema_expression: None,
            schema_expression_sha256: None,
            direct_bindings: Vec::new(),
            referenced_bindings: Vec::new(),
            resolution_status: "resolved".into(),
            resolution_reason: None,
        }
    }

    #[test]
    fn nested_defaults_and_normalizations_keep_json_pointer_paths() {
        let mut compiler = empty_compiler();
        let context = fixture_context("fixture");
        let EvalValue::Schema(schema) = compiler
            .eval_source(
                r#"z.object({ outer: z.object({ name: z.string().toLowerCase().default("N") }) })"#,
                &context,
                0,
            )
            .unwrap()
        else {
            panic!("expected schema")
        };
        assert_eq!(
            schema.defaults[0].schema_path,
            "/properties/outer/properties/name"
        );
        assert_eq!(
            schema.normalizations[0].schema_path,
            "/properties/outer/properties/name"
        );
    }

    #[test]
    fn pinned_raw_acceptance_patterns_cover_date_range_and_sha_case() {
        let mut compiler = empty_compiler();
        for (label, source, expected) in [
            (
                "fixture:DateRangeParam",
                r#"z.string().regex(/^[0-9]+d$/)"#,
                "^((([1-9]|[1-9][0-9]|[1-2][0-9][0-9]|3[0-5][0-9]|36[0-4])[dD]([cC][oO][nN][tT][rR][oO][lL])?)|(([1-9]|[1-4][0-9]|5[0-2])[wW]([cC][oO][nN][tT][rR][oO][lL])?))$",
            ),
            (
                "fixture:Sha256FingerprintParam",
                r#"z.string().regex(/^[a-f0-9]{64}$/)"#,
                "^[A-Fa-f0-9]{64}$",
            ),
        ] {
            let EvalValue::Schema(schema) = compiler
                .eval_source(source, &fixture_context(label), 0)
                .unwrap()
            else {
                panic!("expected schema")
            };
            assert_eq!(schema.schema["pattern"], expected);
        }
    }

    #[test]
    fn nested_unknown_key_policies_are_path_aware() {
        let mut compiler = empty_compiler();
        let EvalValue::Schema(schema) = compiler
            .eval_source(
                r#"z.object({ nested: z.object({ values: z.record(z.string()) }).passthrough() })"#,
                &fixture_context("fixture"),
                0,
            )
            .unwrap()
        else {
            panic!("expected schema")
        };
        assert!(
            schema
                .unknown_key_policies
                .iter()
                .any(|policy| policy.schema_path == "/properties/nested"
                    && policy.behavior == "passthrough")
        );
        assert!(
            schema
                .unknown_key_policies
                .iter()
                .any(
                    |policy| policy.schema_path == "/properties/nested/properties/values"
                        && policy.behavior == "record_values"
                )
        );
    }

    #[test]
    fn dynamic_now_description_requires_exact_pinned_template() {
        let id = "fixture:nowISO".to_string();
        let node = DependencyNode {
            id: id.clone(),
            name: "nowISO".into(),
            file: "fixture.ts".into(),
            blob_oid: "fixture-oid".into(),
            value_kind: "function_declaration".into(),
            declaration: fixture_span(),
            value_span: fixture_span(),
            value_source: "function nowISO()".into(),
            value_sha256: "8e3c6702f40743bc41c34d3cbacd72fc0511f4e9c4766b3c7110cdf2eafc8a6d".into(),
            dependencies: Vec::new(),
        };
        let mut compiler = Compiler {
            nodes: HashMap::from([(id.clone(), &node)]),
            boundaries: HashMap::new(),
            zod_version: Some("4.4.3"),
            cache: HashMap::new(),
            active: Vec::new(),
        };
        let mut context = fixture_context("fixture");
        context.dependencies.insert("nowISO".into(), id);
        let EvalValue::Schema(schema) = compiler
            .eval_source(r#"z.string().describe(`Updated ${nowISO()}`)"#, &context, 0)
            .unwrap()
        else {
            panic!("expected schema")
        };
        assert_eq!(
            schema.annotations[0].source.split("; ").nth(1),
            Some("Updated ${nowISO()}")
        );
        assert!(
            compiler
                .eval_source(
                    r#"z.string().describe(`Updated ${Date.now()}`)"#,
                    &context,
                    0
                )
                .is_err()
        );
    }

    #[test]
    fn registration_overlays_use_account_kinds_and_stack_predicate() {
        assert!(
            context_overlays(&fixture_record("plain", "context:registerTool"))
                .unwrap()
                .is_empty()
        );
        for kind in [
            "context:accountTool",
            "dex:registerTool",
            "casb:accountTool",
        ] {
            let overlays = context_overlays(&fixture_record("account", kind)).unwrap();
            assert_eq!(overlays.len(), 1);
            assert_eq!(
                overlays[0].predicate,
                "accountManager.requiresAccountSelection === true"
            );
        }
        let overlays =
            context_overlays(&fixture_record("search_dev_stack", "context:registerTool")).unwrap();
        assert_eq!(overlays.len(), 1);
        assert!(overlays[0].predicate.contains("unknown-only"));
        assert!(context_overlays(&fixture_record("bad", "unknown")).is_err());
    }

    #[test]
    fn transform_contract_pins_runtime_facts_and_output_shape() {
        let mut compiler = empty_compiler();
        let EvalValue::Schema(schema) = compiler
            .eval_source(
                r#"z.object({ reference: z.string(), offset: z.string() }).transform(() => {})"#,
                &fixture_context("fixture:zTimeframeRelative"),
                0,
            )
            .unwrap()
        else {
            panic!("expected schema")
        };
        let transform = &schema.transforms[0];
        assert_eq!(
            transform.executor,
            "external_runtime; JSON Schema does not execute this transform"
        );
        assert_eq!(
            transform.normalized_output_schema["required"],
            serde_json::json!(["from", "to"])
        );
        assert!(
            transform
                .runtime_validations
                .iter()
                .any(|fact| fact.contains("Date.toISOString"))
        );
    }

    #[test]
    fn canonical_hash_matches_lexicographic_cross_language_vector() {
        let value = json_object([
            ("z", Json::Array(vec![Json::from(3), Json::from(1)])),
            (
                "a",
                json_object([("b", Json::from(2)), ("a", Json::from(1))]),
            ),
        ]);
        assert_eq!(
            String::from_utf8(canonical_json_bytes(&value)).unwrap(),
            r#"{"a":{"a":1,"b":2},"z":[3,1]}"#
        );
        assert_eq!(
            hex_digest(&canonical_json_bytes(&value)),
            "417d5005e689a0abfd6426d6f9848f19ac3c9b252552e58bd670455558c741a7"
        );
    }
}
