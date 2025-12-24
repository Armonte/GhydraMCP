package eu.starsong.ghidra.endpoints;

    import com.google.gson.JsonObject;
    import com.sun.net.httpserver.HttpExchange;
    import com.sun.net.httpserver.HttpServer;
    import ghidra.framework.plugintool.PluginTool;
    import ghidra.program.model.address.GlobalNamespace;
    import ghidra.program.model.listing.Program;
    import ghidra.program.model.symbol.Namespace;
    import ghidra.program.model.symbol.Symbol;
    import ghidra.program.model.symbol.SymbolTable;
    import ghidra.util.Msg;
    import ghidra.util.exception.InvalidInputException;
    import ghidra.program.model.symbol.SourceType;

    import java.io.IOException;
    import java.util.*;

    public class NamespaceEndpoints extends AbstractEndpoint {

        private PluginTool tool;
        
        public NamespaceEndpoints(Program program, int port) {
            super(program, port);
        }
        
        public NamespaceEndpoints(Program program, int port, PluginTool tool) {
            super(program, port);
            this.tool = tool;
        }
        
        @Override
        protected PluginTool getTool() {
            return tool;
        }

        @Override
        public void registerEndpoints(HttpServer server) {
            server.createContext("/namespaces", this::handleNamespaces);
            server.createContext("/namespaces/", this::handleNamespaceByName);
        }

        public void handleNamespaces(HttpExchange exchange) throws IOException {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, String> qparams = parseQueryParams(exchange);
                    int offset = parseIntOrDefault(qparams.get("offset"), 0);
                    int limit = parseIntOrDefault(qparams.get("limit"), 100);
                    
                    Program program = getCurrentProgram();
                    if (program == null) {
                        sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                        return;
                    }
                    
                    Set<String> namespaces = new HashSet<>();
                    for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
                        Namespace ns = symbol.getParentNamespace();
                        if (ns != null && !(ns instanceof GlobalNamespace)) {
                            namespaces.add(ns.getName(true)); // Get fully qualified name
                        }
                    }
                    
                    List<String> sorted = new ArrayList<>(namespaces);
                    Collections.sort(sorted);
                    
                    // Build response with HATEOAS links
                    eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                        .success(true);
                    
                    // Apply pagination and get paginated items
                    List<String> paginated = applyPagination(sorted, offset, limit, builder, "/namespaces");
                    
                    // Set the paginated result
                    builder.result(paginated);
                    
                    // Add program link
                    builder.addLink("program", "/program");
                    
                    sendJsonResponse(exchange, builder.build(), 200);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /namespaces endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }

        /**
         * Handle requests to /namespaces/{name} for GET and PATCH operations
         */
        public void handleNamespaceByName(HttpExchange exchange) throws IOException {
            try {
                String path = exchange.getRequestURI().getPath();
                // Extract namespace name from path like "/namespaces/switchD_801a01b4"
                String namespaceName = path.substring("/namespaces/".length());
                
                // URL decode the namespace name (handles :: separators encoded as %3A%3A)
                namespaceName = java.net.URLDecoder.decode(namespaceName, "UTF-8");
                
                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                    return;
                }
                
                String method = exchange.getRequestMethod();
                
                if ("GET".equals(method)) {
                    handleGetNamespace(exchange, namespaceName);
                } else if ("PATCH".equals(method)) {
                    handlePatchNamespace(exchange, namespaceName);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                Msg.error(this, "Error handling /namespaces/{name} endpoint", e);
                sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }
        
        /**
         * Handle GET request to get namespace information
         */
        private void handleGetNamespace(HttpExchange exchange, String namespaceName) throws IOException {
            Program program = getCurrentProgram();
            Namespace namespace = findNamespace(program, namespaceName);
            
            if (namespace == null) {
                sendErrorResponse(exchange, 404, "Namespace not found: " + namespaceName, "NAMESPACE_NOT_FOUND");
                return;
            }
            
            Map<String, Object> namespaceInfo = new HashMap<>();
            namespaceInfo.put("name", namespace.getName());
            namespaceInfo.put("fullName", namespace.getName(true));
            namespaceInfo.put("isGlobal", namespace.isGlobal());
            
            // Count symbols in this namespace
            int symbolCount = 0;
            for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
                if (symbol.getParentNamespace().equals(namespace)) {
                    symbolCount++;
                }
            }
            namespaceInfo.put("symbolCount", symbolCount);
            
            eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                .success(true)
                .result(namespaceInfo);
            builder.addLink("self", "/namespaces/" + java.net.URLEncoder.encode(namespaceName, "UTF-8"));
            builder.addLink("program", "/program");
            
            sendJsonResponse(exchange, builder.build(), 200);
        }
        
        /**
         * Handle PATCH request to rename a namespace
         */
        private void handlePatchNamespace(HttpExchange exchange, String namespaceName) throws IOException {
            Map<String, String> params = parseJsonPostParams(exchange);
            Program program = getCurrentProgram();
            SymbolTable symbolTable = program.getSymbolTable();
            
            String newName = params.get("name");
            if (newName == null || newName.isEmpty()) {
                sendErrorResponse(exchange, 400, "New namespace name is required", "MISSING_PARAMETER");
                return;
            }
            
            try {
                Namespace namespace = findNamespace(program, namespaceName);
                if (namespace == null) {
                    sendErrorResponse(exchange, 404, "Namespace not found: " + namespaceName, "NAMESPACE_NOT_FOUND");
                    return;
                }
                
                // Cannot rename Global namespace
                if (namespace instanceof GlobalNamespace) {
                    sendErrorResponse(exchange, 400, "Cannot rename Global namespace", "INVALID_OPERATION");
                    return;
                }
                
                int transactionID = program.startTransaction("Rename Namespace");
                try {
                    // Get the symbol for this namespace and rename it
                    Symbol namespaceSymbol = namespace.getSymbol();
                    if (namespaceSymbol != null) {
                        namespaceSymbol.setName(newName, SourceType.USER_DEFINED);
                    }
                    
                    // Get updated namespace info
                    Namespace updatedNamespace = findNamespace(program, newName);
                    if (updatedNamespace == null) {
                        updatedNamespace = namespace; // Fallback
                    }
                    
                    Map<String, Object> namespaceInfo = new HashMap<>();
                    namespaceInfo.put("name", updatedNamespace.getName());
                    namespaceInfo.put("fullName", updatedNamespace.getName(true));
                    namespaceInfo.put("isGlobal", updatedNamespace.isGlobal());
                    namespaceInfo.put("oldName", namespaceName);
                    
                    eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                        .success(true)
                        .result(namespaceInfo);
                    builder.addLink("self", "/namespaces/" + java.net.URLEncoder.encode(newName, "UTF-8"));
                    builder.addLink("program", "/program");
                    
                    sendJsonResponse(exchange, builder.build(), 200);
                } finally {
                    program.endTransaction(transactionID, true);
                }
            } catch (InvalidInputException e) {
                sendErrorResponse(exchange, 400, "Invalid namespace name: " + e.getMessage(), "INVALID_INPUT");
            } catch (Exception e) {
                sendErrorResponse(exchange, 500, "Error renaming namespace: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }
        
        /**
         * Find a namespace by name (supports fully qualified names with :: separator)
         */
        private Namespace findNamespace(Program program, String namespaceName) {
            SymbolTable symbolTable = program.getSymbolTable();
            Namespace globalNamespace = program.getGlobalNamespace();
            
            // Handle fully qualified names like "switchD_801a01b4" or "Global::MyNamespace"
            if (namespaceName.contains("::")) {
                String[] parts = namespaceName.split("::");
                Namespace current = globalNamespace;
                
                for (String part : parts) {
                    Symbol nsSymbol = symbolTable.getNamespaceSymbol(part, current);
                    if (nsSymbol == null) {
                        return null;
                    }
                    Object nsObj = nsSymbol.getObject();
                    if (nsObj instanceof Namespace) {
                        current = (Namespace) nsObj;
                    } else {
                        return null;
                    }
                }
                return current;
            }
            
            // Try global namespace first
            if ("Global".equals(namespaceName) || namespaceName.isEmpty()) {
                return globalNamespace;
            }
            
            // Try to find namespace in global scope
            Symbol nsSymbol = symbolTable.getNamespaceSymbol(namespaceName, globalNamespace);
            if (nsSymbol != null) {
                Object nsObj = nsSymbol.getObject();
                if (nsObj instanceof Namespace) {
                    return (Namespace) nsObj;
                }
            }
            
            // If not found, try searching all namespaces
            for (Symbol symbol : symbolTable.getAllSymbols(true)) {
                Namespace ns = symbol.getParentNamespace();
                if (ns != null && ns.getName().equals(namespaceName)) {
                    return ns;
                }
                if (ns != null && ns.getName(true).equals(namespaceName)) {
                    return ns;
                }
            }
            
            return null;
        }

        // parseIntOrDefault is inherited from AbstractEndpoint
    }
