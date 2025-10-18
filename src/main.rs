use std::collections::{HashMap, HashSet};
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::{
    Diagnostic, DiagnosticSeverity, DidChangeTextDocumentParams, DidCloseTextDocumentParams,
    DidOpenTextDocumentParams, GotoDefinitionParams, GotoDefinitionResponse, InitializeParams,
    InitializeResult, InitializedParams, Location, MessageType, OneOf, Position, Range,
    ReferenceParams, SemanticToken, SemanticTokenType, SemanticTokens, SemanticTokensFullOptions,
    SemanticTokensLegend, SemanticTokensOptions, SemanticTokensParams, SemanticTokensResult,
    SemanticTokensServerCapabilities, ServerCapabilities, ServerInfo, TextDocumentSyncCapability,
    TextDocumentSyncKind, TextDocumentSyncOptions, Url,
};
use tower_lsp::{Client, LanguageServer, LspService, Server};
use tree_sitter::{Language, Node, Parser};

#[derive(Clone, Debug)]
struct Definition {
    name: String,
    range: Range,
    start_byte: usize,
    end_byte: usize,
}

struct Backend {
    client: Client,
    language: Language,
    documents: tokio::sync::RwLock<HashMap<Url, String>>,
    definitions: tokio::sync::RwLock<HashMap<Url, Vec<Definition>>>,
    symbol_index: tokio::sync::RwLock<HashMap<String, Vec<Location>>>,
}

impl Backend {
    fn new(client: Client) -> Self {
        Self {
            client,
            language: tree_sitter_asn1::LANGUAGE.into(),
            documents: tokio::sync::RwLock::new(HashMap::new()),
            definitions: tokio::sync::RwLock::new(HashMap::new()),
            symbol_index: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    async fn parse_and_publish(&self, uri: &Url) {
        let text = {
            let documents = self.documents.read().await;
            match documents.get(uri) {
                Some(text) => text.clone(),
                None => return,
            }
        };

        let mut parser = Parser::new();
        if parser.set_language(&self.language).is_err() {
            self.client
                .log_message(
                    MessageType::ERROR,
                    "Failed to load ASN.1 grammar for parsing".to_string(),
                )
                .await;
            return;
        }

        let (diagnostics, definitions) = match parser.parse(&text, None) {
            Some(tree) => {
                let root = tree.root_node();
                let definitions = Self::collect_definitions(root, &text);
                let definition_count = definitions.len();

                if root.has_error() {
                    self.client
                        .log_message(
                            MessageType::WARNING,
                            format!(
                                "Parse errors detected in {} ({} definitions indexed)",
                                uri, definition_count
                            ),
                        )
                        .await;
                    (Self::error_diagnostics(root), definitions)
                } else {
                    self.client
                        .log_message(
                            MessageType::INFO,
                            format!(
                                "Parsed {} with {} definitions",
                                uri.path(),
                                definition_count
                            ),
                        )
                        .await;
                    (Vec::new(), definitions)
                }
            }
            None => (
                vec![Diagnostic {
                    range: Range::default(),
                    severity: Some(DiagnosticSeverity::ERROR),
                    message: "Failed to parse document".to_string(),
                    ..Default::default()
                }],
                Vec::new(),
            ),
        };

        self.client
            .publish_diagnostics(uri.clone(), diagnostics, None)
            .await;
        self.update_symbol_index(uri, &definitions).await;
        self.definitions
            .write()
            .await
            .insert(uri.clone(), definitions);
    }

    fn error_diagnostics(root: Node) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();
        let mut stack = vec![root];

        while let Some(node) = stack.pop() {
            if node.is_error() {
                diagnostics.push(Diagnostic {
                    range: Range {
                        start: Position {
                            line: node.start_position().row as u32,
                            character: node.start_position().column as u32,
                        },
                        end: Position {
                            line: node.end_position().row as u32,
                            character: node.end_position().column as u32,
                        },
                    },
                    severity: Some(DiagnosticSeverity::ERROR),
                    message: "Syntax error".to_string(),
                    ..Default::default()
                });
            }

            if node.has_error() {
                let mut cursor = node.walk();
                if cursor.goto_first_child() {
                    loop {
                        stack.push(cursor.node());
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
            }
        }

        // If we didn't find any explicit error nodes, fall back to a document-wide diagnostic.
        if diagnostics.is_empty() && root.has_error() {
            diagnostics.push(Diagnostic {
                range: Range::default(),
                severity: Some(DiagnosticSeverity::ERROR),
                message: "Syntax error".to_string(),
                ..Default::default()
            });
        }

        diagnostics
    }

    fn collect_definitions(root: Node, source: &str) -> Vec<Definition> {
        const DEFINITION_KINDS: &[&str] = &[
            "module_identity_assignment",
            "module_compliance_assignment",
            "object_group_assignment",
            "notification_group_assignment",
            "agent_capabilities_assignment",
            "object_identity_assignment",
            "object_identifier_assignment",
            "object_type_assignment",
            "notification_type_assignment",
            "trap_type_assignment",
            "textual_convention_definition",
            "type_assignment",
        ];

        let mut definitions = Vec::new();
        let mut stack = vec![root];

        while let Some(node) = stack.pop() {
            if DEFINITION_KINDS.iter().any(|kind| node.kind() == *kind) {
                if let Some(name_node) = node.named_child(0) {
                    let start = name_node.start_byte();
                    let end = name_node.end_byte();
                    if end <= source.len() {
                        let name = source[start..end].to_string();
                        definitions.push(Definition {
                            name,
                            range: Range {
                                start: Position {
                                    line: name_node.start_position().row as u32,
                                    character: name_node.start_position().column as u32,
                                },
                                end: Position {
                                    line: name_node.end_position().row as u32,
                                    character: name_node.end_position().column as u32,
                                },
                            },
                            start_byte: start,
                            end_byte: end,
                        });
                    }
                }

                continue;
            }

            let mut cursor = node.walk();
            if cursor.goto_first_child() {
                loop {
                    stack.push(cursor.node());
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        }

        definitions
    }

    async fn update_symbol_index(&self, uri: &Url, definitions: &[Definition]) {
        let mut index = self.symbol_index.write().await;

        for locations in index.values_mut() {
            locations.retain(|location| location.uri != *uri);
        }
        index.retain(|_, locations| !locations.is_empty());

        for definition in definitions {
            index
                .entry(definition.name.clone())
                .or_default()
                .push(Location {
                    uri: uri.clone(),
                    range: definition.range,
                });
        }
    }

    fn symbol_at_position(text: &str, position: Position) -> Option<String> {
        let line_index = position.line as usize;
        let character_index = position.character as usize;
        let line = text.split('\n').nth(line_index)?;

        let line_char_count = line.chars().count();
        if character_index > line_char_count {
            return None;
        }

        let byte_index = Self::byte_index_at(line, character_index)?;
        let mut start = byte_index;
        let mut end = byte_index;
        let bytes = line.as_bytes();

        while start > 0 && Self::is_symbol_byte(bytes[start - 1]) {
            start -= 1;
        }

        while end < bytes.len() && Self::is_symbol_byte(bytes[end]) {
            end += 1;
        }

        if start == end {
            return None;
        }

        Some(line[start..end].to_string())
    }

    fn byte_index_at(line: &str, character_index: usize) -> Option<usize> {
        let char_count = line.chars().count();
        if character_index > char_count {
            return None;
        }

        if character_index == char_count {
            Some(line.len())
        } else {
            line.char_indices()
                .nth(character_index)
                .map(|(byte_index, _)| byte_index)
        }
    }

    fn is_symbol_byte(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
    }

    async fn semantic_tokens_data(&self, uri: &Url) -> Option<Vec<SemanticToken>> {
        let text = {
            let documents = self.documents.read().await;
            documents.get(uri)?.clone()
        };

        let mut parser = Parser::new();
        if parser.set_language(&self.language).is_err() {
            self.client
                .log_message(
                    MessageType::ERROR,
                    "Failed to load ASN.1 grammar for semantic tokens".to_string(),
                )
                .await;
            return None;
        }

        let tree = parser.parse(&text, None)?;
        let root = tree.root_node();
        let definitions = Self::collect_definitions(root, &text);
        let definition_spans: HashSet<(usize, usize)> = definitions
            .iter()
            .map(|d| (d.start_byte, d.end_byte))
            .collect();

        Some(Self::collect_semantic_tokens(
            &text,
            root,
            &definition_spans,
        ))
    }
}

const SEMANTIC_TOKEN_TYPES: &[SemanticTokenType] = &[
    SemanticTokenType::COMMENT,
    SemanticTokenType::STRING,
    SemanticTokenType::NUMBER,
    SemanticTokenType::NAMESPACE,
    SemanticTokenType::TYPE,
    SemanticTokenType::VARIABLE,
    SemanticTokenType::MACRO,
    SemanticTokenType::KEYWORD,
];

#[derive(Clone, Copy)]
enum SemanticKind {
    Comment,
    String,
    Number,
    Namespace,
    Type,
    Variable,
    Macro,
    Keyword,
}

impl SemanticKind {
    const fn index(self) -> u32 {
        match self {
            SemanticKind::Comment => 0,
            SemanticKind::String => 1,
            SemanticKind::Number => 2,
            SemanticKind::Namespace => 3,
            SemanticKind::Type => 4,
            SemanticKind::Variable => 5,
            SemanticKind::Macro => 6,
            SemanticKind::Keyword => 7,
        }
    }
}

#[derive(Clone, Copy)]
struct SemanticTokenData {
    line: u32,
    start_char: u32,
    length: u32,
    token_type: u32,
    modifiers: u32,
}

impl Backend {
    fn collect_semantic_tokens(
        text: &str,
        root: Node,
        definition_spans: &HashSet<(usize, usize)>,
    ) -> Vec<SemanticToken> {
        let mut tokens = Vec::new();
        let line_offsets = line_start_offsets(text);
        let mut stack = vec![root];

        while let Some(node) = stack.pop() {
            Self::push_semantic_token(&mut tokens, node, text, &line_offsets, definition_spans);

            let mut cursor = node.walk();
            if cursor.goto_first_child() {
                loop {
                    stack.push(cursor.node());
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        }

        tokens.sort_by(|a, b| match a.line.cmp(&b.line) {
            std::cmp::Ordering::Equal => a.start_char.cmp(&b.start_char),
            other => other,
        });

        encode_semantic_tokens(tokens)
    }

    fn push_semantic_token(
        tokens: &mut Vec<SemanticTokenData>,
        node: Node,
        text: &str,
        line_offsets: &[usize],
        definition_spans: &HashSet<(usize, usize)>,
    ) {
        let kind = match node.kind() {
            "comment" => Some(SemanticKind::Comment),
            "string" | "hex_string" | "binary_string" => Some(SemanticKind::String),
            "number" => Some(SemanticKind::Number),
            "module_identifier" => Some(SemanticKind::Namespace),
            "identifier" => Some(SemanticKind::Type),
            "symbol" => {
                let span = (node.start_byte(), node.end_byte());
                if definition_spans.contains(&span) {
                    Some(SemanticKind::Macro)
                } else {
                    Some(SemanticKind::Variable)
                }
            }
            other if is_keyword(other) => Some(SemanticKind::Keyword),
            _ => None,
        };

        let Some(kind) = kind else {
            return;
        };

        push_token_for_node(tokens, node, text, line_offsets, kind);
    }
}

fn encode_semantic_tokens(tokens: Vec<SemanticTokenData>) -> Vec<SemanticToken> {
    let mut data = Vec::with_capacity(tokens.len());
    let mut prev_line = 0;
    let mut prev_start = 0;

    for token in tokens {
        let delta_line = token.line.saturating_sub(prev_line);
        let delta_start = if delta_line == 0 {
            token.start_char.saturating_sub(prev_start)
        } else {
            token.start_char
        };

        data.push(SemanticToken {
            delta_line,
            delta_start,
            length: token.length,
            token_type: token.token_type,
            token_modifiers_bitset: token.modifiers,
        });

        prev_line = token.line;
        prev_start = token.start_char;
    }

    data
}

fn push_token_for_node(
    tokens: &mut Vec<SemanticTokenData>,
    node: Node,
    text: &str,
    line_offsets: &[usize],
    kind: SemanticKind,
) {
    let start_position = node.start_position();
    let end_position = node.end_position();
    let start_line = start_position.row as usize;
    let end_line = end_position.row as usize;
    let start_byte = node.start_byte();
    let end_byte = node.end_byte();

    if start_line == end_line {
        push_single_line_token(
            tokens,
            text,
            line_offsets,
            start_line,
            start_byte,
            end_byte,
            kind,
        );
    } else {
        for line in start_line..=end_line {
            let line_start = line_offsets.get(line).copied().unwrap_or(0);
            let line_end = line_end_offset(text, line_offsets, line);
            let token_start = if line == start_line {
                start_byte
            } else {
                line_start
            };
            let token_end = if line == end_line {
                end_byte
            } else {
                line_end.min(end_byte)
            };

            if token_start >= token_end {
                continue;
            }

            push_single_line_token(
                tokens,
                text,
                line_offsets,
                line,
                token_start,
                token_end,
                kind,
            );
        }
    }
}

fn push_single_line_token(
    tokens: &mut Vec<SemanticTokenData>,
    text: &str,
    line_offsets: &[usize],
    line: usize,
    start_byte: usize,
    end_byte: usize,
    kind: SemanticKind,
) {
    let line_start = line_offsets.get(line).copied().unwrap_or(0);
    let start_slice = &text[line_start..start_byte];
    let token_slice = &text[start_byte..end_byte];
    let start_char = utf16_len(start_slice);
    let length = utf16_len(token_slice);

    if length == 0 {
        return;
    }

    tokens.push(SemanticTokenData {
        line: line as u32,
        start_char,
        length,
        token_type: kind.index(),
        modifiers: 0,
    });
}

fn line_start_offsets(text: &str) -> Vec<usize> {
    let mut offsets = vec![0];
    for (idx, ch) in text.char_indices() {
        if ch == '\n' {
            offsets.push(idx + ch.len_utf8());
        }
    }
    offsets
}

fn line_end_offset(text: &str, offsets: &[usize], line: usize) -> usize {
    let start = offsets.get(line).copied().unwrap_or(0);
    let end = if let Some(next) = offsets.get(line + 1).copied() {
        next
    } else {
        text.len()
    };

    let mut trimmed_end = end;
    while trimmed_end > start {
        let ch = text.as_bytes()[trimmed_end - 1];
        if ch == b'\n' || ch == b'\r' {
            trimmed_end -= 1;
        } else {
            break;
        }
    }

    trimmed_end
}

fn utf16_len(text: &str) -> u32 {
    text.encode_utf16().count() as u32
}

fn is_keyword(kind: &str) -> bool {
    matches!(
        kind,
        "ACCESS"
            | "AGENT-CAPABILITIES"
            | "ALL"
            | "AUGMENTS"
            | "BEGIN"
            | "BITS"
            | "CONTACT-INFO"
            | "DEFINITIONS"
            | "DEFVAL"
            | "DESCRIPTION"
            | "DISPLAY-HINT"
            | "END"
            | "ENTERPRISE"
            | "EXPORTS"
            | "FROM"
            | "GROUP"
            | "IMPLIED"
            | "IMPORTS"
            | "INCLUDES"
            | "INDEX"
            | "INTEGER"
            | "LAST-UPDATED"
            | "MANDATORY-GROUPS"
            | "MAX-ACCESS"
            | "MIN-ACCESS"
            | "MODULE"
            | "MODULE-COMPLIANCE"
            | "MODULE-IDENTITY"
            | "NOTIFICATION-GROUP"
            | "NOTIFICATION-TYPE"
            | "NOTIFICATIONS"
            | "OBJECT"
            | "OBJECT-GROUP"
            | "OBJECT-IDENTITY"
            | "OBJECT-TYPE"
            | "OBJECTS"
            | "OF"
            | "ORGANIZATION"
            | "PRODUCT-RELEASE"
            | "REFERENCE"
            | "REVISION"
            | "SEQUENCE"
            | "STATUS"
            | "SUPPORTS"
            | "SYNTAX"
            | "TEXTUAL-CONVENTION"
            | "TRAP-TYPE"
            | "UNITS"
            | "VARIABLES"
            | "VARIATION"
            | "WRITE-SYNTAX"
    )
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        self.client
            .log_message(MessageType::INFO, "asn1-lsp initializing")
            .await;

        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                definition_provider: Some(OneOf::Left(true)),
                references_provider: Some(OneOf::Left(true)),
                text_document_sync: Some(TextDocumentSyncCapability::Options(
                    TextDocumentSyncOptions {
                        open_close: Some(true),
                        change: Some(TextDocumentSyncKind::FULL),
                        ..Default::default()
                    },
                )),
                semantic_tokens_provider: Some(
                    SemanticTokensServerCapabilities::SemanticTokensOptions(
                        SemanticTokensOptions {
                            work_done_progress_options: Default::default(),
                            legend: SemanticTokensLegend {
                                token_types: SEMANTIC_TOKEN_TYPES.to_vec(),
                                token_modifiers: Vec::new(),
                            },
                            range: Some(false),
                            full: Some(SemanticTokensFullOptions::Bool(true)),
                        },
                    ),
                ),
                ..Default::default()
            },
            server_info: Some(ServerInfo {
                name: "asn1-lsp".to_string(),
                version: None,
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "asn1-lsp ready")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        self.client
            .log_message(MessageType::INFO, "asn1-lsp shutting down")
            .await;
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri;
        let text = params.text_document.text;
        self.documents.write().await.insert(uri.clone(), text);

        self.parse_and_publish(&uri).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri;
        let new_text = params
            .content_changes
            .into_iter()
            .last()
            .map(|change| change.text)
            .unwrap_or_default();

        self.documents.write().await.insert(uri.clone(), new_text);

        self.parse_and_publish(&uri).await;
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;
        self.documents.write().await.remove(&uri);
        self.definitions.write().await.remove(&uri);
        self.update_symbol_index(&uri, &[]).await;
        self.client.publish_diagnostics(uri, Vec::new(), None).await;
    }

    async fn goto_definition(
        &self,
        params: GotoDefinitionParams,
    ) -> Result<Option<GotoDefinitionResponse>> {
        let text_document_position = params.text_document_position_params;
        let uri = text_document_position.text_document.uri;
        let position = text_document_position.position;

        let symbol = {
            let documents = self.documents.read().await;
            documents
                .get(&uri)
                .and_then(|text| Self::symbol_at_position(text, position))
        };

        let Some(symbol) = symbol else {
            return Ok(None);
        };

        let locations = {
            let index = self.symbol_index.read().await;
            index.get(&symbol).cloned().unwrap_or_default()
        };

        if locations.is_empty() {
            return Ok(None);
        }

        Ok(Some(GotoDefinitionResponse::Array(locations)))
    }

    async fn references(&self, _: ReferenceParams) -> Result<Option<Vec<Location>>> {
        // TODO: Track symbol usages across the workspace.
        Ok(None)
    }

    async fn semantic_tokens_full(
        &self,
        params: SemanticTokensParams,
    ) -> Result<Option<SemanticTokensResult>> {
        let uri = params.text_document.uri;
        let data = self.semantic_tokens_data(&uri).await;

        Ok(data.map(|data| {
            SemanticTokensResult::Tokens(SemanticTokens {
                result_id: None,
                data,
            })
        }))
    }
}

#[tokio::main]
async fn main() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(Backend::new);
    Server::new(stdin, stdout, socket).serve(service).await;
}
