use std::collections::HashMap;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::{
    Diagnostic, DiagnosticSeverity, DidChangeTextDocumentParams, DidCloseTextDocumentParams,
    DidOpenTextDocumentParams, GotoDefinitionParams, GotoDefinitionResponse, InitializeParams,
    InitializeResult, InitializedParams, Location, MessageType, OneOf, Position, Range,
    ReferenceParams, ServerCapabilities, ServerInfo, TextDocumentSyncCapability,
    TextDocumentSyncKind, TextDocumentSyncOptions, Url,
};
use tower_lsp::{Client, LanguageServer, LspService, Server};
use tree_sitter::{Language, Node, Parser};

#[derive(Clone, Debug)]
struct Definition {
    name: String,
    range: Range,
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
}

#[tokio::main]
async fn main() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(Backend::new);
    Server::new(stdin, stdout, socket).serve(service).await;
}
