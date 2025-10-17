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

struct Backend {
    client: Client,
    language: Language,
    documents: tokio::sync::RwLock<HashMap<Url, String>>,
}

impl Backend {
    fn new(client: Client) -> Self {
        Self {
            client,
            language: tree_sitter_asn1::LANGUAGE.into(),
            documents: tokio::sync::RwLock::new(HashMap::new()),
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

        let diagnostics = match parser.parse(&text, None) {
            Some(tree) => {
                if tree.root_node().has_error() {
                    self.client
                        .log_message(
                            MessageType::WARNING,
                            format!("Parse errors detected in {}", uri),
                        )
                        .await;
                    Self::error_diagnostics(tree.root_node())
                } else {
                    self.client
                        .log_message(MessageType::INFO, format!("Parsed {}", uri.path()))
                        .await;
                    Vec::new()
                }
            }
            None => {
                vec![Diagnostic {
                    range: Range::default(),
                    severity: Some(DiagnosticSeverity::ERROR),
                    message: "Failed to parse document".to_string(),
                    ..Default::default()
                }]
            }
        };

        self.client
            .publish_diagnostics(uri.clone(), diagnostics, None)
            .await;
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
            ..Default::default()
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
        self.client.publish_diagnostics(uri, Vec::new(), None).await;
    }

    async fn goto_definition(
        &self,
        _: GotoDefinitionParams,
    ) -> Result<Option<GotoDefinitionResponse>> {
        // TODO: Parse the syntax tree and resolve ASN.1 symbol definitions.
        Ok(None)
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
