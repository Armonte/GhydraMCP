package eu.starsong.ghidra.endpoints;

    import com.google.gson.JsonObject;
    import com.sun.net.httpserver.HttpExchange;
    import com.sun.net.httpserver.HttpServer;
    import ghidra.framework.plugintool.PluginTool;
    import ghidra.program.model.address.Address;
    import ghidra.program.model.listing.Program;
    import ghidra.program.model.symbol.Namespace;
    import ghidra.program.model.symbol.Symbol;
    import ghidra.program.model.symbol.SymbolIterator;
    import ghidra.program.model.symbol.SymbolTable;
    import ghidra.util.Msg;
    import ghidra.util.exception.InvalidInputException;
    import ghidra.program.model.symbol.SourceType;
    import ghidra.program.model.address.GlobalNamespace;

    import java.io.IOException;
    import java.util.*;

    public class SymbolEndpoints extends AbstractEndpoint {

        private PluginTool tool;
        
        // Updated constructor to accept port
        public SymbolEndpoints(Program program, int port) {
            super(program, port); // Call super constructor
        }
        
        public SymbolEndpoints(Program program, int port, PluginTool tool) {
            super(program, port);
            this.tool = tool;
        }
        
        @Override
        protected PluginTool getTool() {
            return tool;
        }

        @Override
        public void registerEndpoints(HttpServer server) {
            server.createContext("/symbols/imports", this::handleImports);
            server.createContext("/symbols/exports", this::handleExports);
            server.createContext("/symbols", this::handleSymbols);
            // Register dynamic handler for /symbols/{address} paths
            server.createContext("/symbols/", this::handleSymbolByAddress);
        }
        
        public void handleSymbols(HttpExchange exchange) throws IOException {
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
                    
                    List<Map<String, Object>> symbols = new ArrayList<>();
                    SymbolTable symbolTable = program.getSymbolTable();
                    SymbolIterator symbolIterator = symbolTable.getAllSymbols(true);
                    
                    while (symbolIterator.hasNext()) {
                        Symbol symbol = symbolIterator.next();
                        Map<String, Object> symbolInfo = new HashMap<>();
                        symbolInfo.put("name", symbol.getName());
                        symbolInfo.put("address", symbol.getAddress().toString());
                        symbolInfo.put("namespace", symbol.getParentNamespace().getName());
                        symbolInfo.put("type", symbol.getSymbolType().toString());
                        symbolInfo.put("isPrimary", symbol.isPrimary());
                        
                        // Add HATEOAS links
                        Map<String, Object> links = new HashMap<>();
                        Map<String, String> selfLink = new HashMap<>();
                        selfLink.put("href", "/symbols/" + symbol.getAddress().toString());
                        links.put("self", selfLink);
                        symbolInfo.put("_links", links);
                        
                        symbols.add(symbolInfo);
                    }
                    
                    // Build response with HATEOAS links
                    eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                        .success(true);
                    
                    // Apply pagination and get paginated items
                    List<Map<String, Object>> paginatedSymbols = applyPagination(symbols, offset, limit, builder, "/symbols");
                    
                    // Set the paginated result
                    builder.result(paginatedSymbols);
                    
                    // Add program link
                    builder.addLink("program", "/program");
                    
                    sendJsonResponse(exchange, builder.build(), 200);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                Msg.error(this, "Error handling /symbols endpoint", e);
                sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }

        public void handleImports(HttpExchange exchange) throws IOException {
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
                    
                    List<Map<String, Object>> imports = new ArrayList<>();
                    for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
                        Map<String, Object> imp = new HashMap<>();
                        imp.put("name", symbol.getName());
                        imp.put("address", symbol.getAddress().toString());
                        
                        // Add HATEOAS links
                        Map<String, Object> links = new HashMap<>();
                        Map<String, String> selfLink = new HashMap<>();
                        selfLink.put("href", "/symbols/imports/" + symbol.getAddress().toString());
                        links.put("self", selfLink);
                        imp.put("_links", links);
                        
                        imports.add(imp);
                    }
                    
                    // Build response with HATEOAS links
                    eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                        .success(true);
                    
                    // Apply pagination and get paginated items
                    List<Map<String, Object>> paginated = applyPagination(imports, offset, limit, builder, "/symbols/imports");
                    
                    // Set the paginated result
                    builder.result(paginated);
                    
                    // Add additional links
                    builder.addLink("program", "/program");
                    builder.addLink("symbols", "/symbols");
                    
                    sendJsonResponse(exchange, builder.build(), 200);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /symbols/imports endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }

        public void handleExports(HttpExchange exchange) throws IOException {
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
                    
                    List<Map<String, Object>> exports = new ArrayList<>();
                    SymbolTable table = program.getSymbolTable();
                    SymbolIterator it = table.getAllSymbols(true);
                    
                    while (it.hasNext()) {
                        Symbol s = it.next();
                        if (s.isExternalEntryPoint()) {
                            Map<String, Object> exp = new HashMap<>();
                            exp.put("name", s.getName());
                            exp.put("address", s.getAddress().toString());
                            
                            // Add HATEOAS links
                            Map<String, Object> links = new HashMap<>();
                            Map<String, String> selfLink = new HashMap<>();
                            selfLink.put("href", "/symbols/exports/" + s.getAddress().toString());
                            links.put("self", selfLink);
                            exp.put("_links", links);
                            
                            exports.add(exp);
                        }
                    }
                    
                    // Build response with HATEOAS links
                    eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                        .success(true);
                    
                    // Apply pagination and get paginated items
                    List<Map<String, Object>> paginated = applyPagination(exports, offset, limit, builder, "/symbols/exports");
                    
                    // Set the paginated result
                    builder.result(paginated);
                    
                    // Add additional links
                    builder.addLink("program", "/program");
                    builder.addLink("symbols", "/symbols");
                    
                    sendJsonResponse(exchange, builder.build(), 200);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /symbols/exports endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }

        /**
         * Handle requests to /symbols/{address} for GET, PATCH, DELETE operations
         */
        public void handleSymbolByAddress(HttpExchange exchange) throws IOException {
            try {
                String path = exchange.getRequestURI().getPath();
                // Extract address from path like "/symbols/0x801a01b4" or "/symbols/801a01b4"
                String addressStr = path.substring("/symbols/".length());
                
                // Remove any trailing slashes or additional path segments
                if (addressStr.contains("/")) {
                    addressStr = addressStr.substring(0, addressStr.indexOf("/"));
                }
                
                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                    return;
                }
                
                Address address = resolveAddress(program, addressStr);
                if (address == null) {
                    sendErrorResponse(exchange, 400, "Invalid address: " + addressStr, "INVALID_ADDRESS");
                    return;
                }
                
                String method = exchange.getRequestMethod();
                
                if ("GET".equals(method)) {
                    handleGetSymbol(exchange, address);
                } else if ("PATCH".equals(method)) {
                    handlePatchSymbol(exchange, address);
                } else if ("DELETE".equals(method)) {
                    handleDeleteSymbol(exchange, address);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                Msg.error(this, "Error handling /symbols/{address} endpoint", e);
                sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }
        
        /**
         * Handle GET request to get symbol details at an address
         */
        private void handleGetSymbol(HttpExchange exchange, Address address) throws IOException {
            Program program = getCurrentProgram();
            SymbolTable symbolTable = program.getSymbolTable();
            Symbol symbol = symbolTable.getPrimarySymbol(address);
            
            if (symbol == null) {
                sendErrorResponse(exchange, 404, "No symbol found at address: " + address, "SYMBOL_NOT_FOUND");
                return;
            }
            
            Map<String, Object> symbolInfo = new HashMap<>();
            symbolInfo.put("name", symbol.getName());
            symbolInfo.put("address", symbol.getAddress().toString());
            symbolInfo.put("namespace", symbol.getParentNamespace().getName());
            symbolInfo.put("type", symbol.getSymbolType().toString());
            symbolInfo.put("isPrimary", symbol.isPrimary());
            
            eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                .success(true)
                .result(symbolInfo);
            builder.addLink("self", "/symbols/" + address.toString());
            builder.addLink("program", "/program");
            
            sendJsonResponse(exchange, builder.build(), 200);
        }
        
        /**
         * Handle PATCH request to modify symbol properties (name, namespace)
         */
        private void handlePatchSymbol(HttpExchange exchange, Address address) throws IOException {
            Map<String, String> params = parseJsonPostParams(exchange);
            Program program = getCurrentProgram();
            SymbolTable symbolTable = program.getSymbolTable();
            
            try {
                int transactionID = program.startTransaction("Modify Symbol");
                try {
                    Symbol symbol = symbolTable.getPrimarySymbol(address);
                    if (symbol == null) {
                        sendErrorResponse(exchange, 404, "No symbol found at address: " + address, "SYMBOL_NOT_FOUND");
                        return;
                    }
                    
                    boolean modified = false;
                    String newName = params.get("name");
                    String newNamespace = params.get("namespace");
                    
                    // Rename symbol if name is provided
                    if (newName != null && !newName.isEmpty() && !newName.equals(symbol.getName())) {
                        symbol.setName(newName, SourceType.USER_DEFINED);
                        modified = true;
                    }
                    
                    // Change namespace if provided
                    if (newNamespace != null && !newNamespace.isEmpty()) {
                        Namespace targetNamespace = findNamespace(program, newNamespace);
                        if (targetNamespace == null) {
                            sendErrorResponse(exchange, 400, "Namespace not found: " + newNamespace, "NAMESPACE_NOT_FOUND");
                            return;
                        }
                        symbol.setNamespace(targetNamespace);
                        modified = true;
                    }
                    
                    if (!modified) {
                        sendErrorResponse(exchange, 400, "No valid modifications provided", "NO_MODIFICATIONS");
                        return;
                    }
                    
                    // Get updated symbol info
                    Symbol updatedSymbol = symbolTable.getPrimarySymbol(address);
                    Map<String, Object> symbolInfo = new HashMap<>();
                    symbolInfo.put("name", updatedSymbol.getName());
                    symbolInfo.put("address", updatedSymbol.getAddress().toString());
                    symbolInfo.put("namespace", updatedSymbol.getParentNamespace().getName());
                    symbolInfo.put("type", updatedSymbol.getSymbolType().toString());
                    symbolInfo.put("isPrimary", updatedSymbol.isPrimary());
                    
                    eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                        .success(true)
                        .result(symbolInfo);
                    builder.addLink("self", "/symbols/" + address.toString());
                    builder.addLink("program", "/program");
                    
                    sendJsonResponse(exchange, builder.build(), 200);
                } finally {
                    program.endTransaction(transactionID, true);
                }
            } catch (InvalidInputException e) {
                sendErrorResponse(exchange, 400, "Invalid input: " + e.getMessage(), "INVALID_INPUT");
            } catch (Exception e) {
                sendErrorResponse(exchange, 500, "Error modifying symbol: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }
        
        /**
         * Handle DELETE request to remove symbol at address
         */
        private void handleDeleteSymbol(HttpExchange exchange, Address address) throws IOException {
            Program program = getCurrentProgram();
            SymbolTable symbolTable = program.getSymbolTable();
            
            try {
                int transactionID = program.startTransaction("Delete Symbol");
                try {
                    Symbol symbol = symbolTable.getPrimarySymbol(address);
                    if (symbol == null) {
                        sendErrorResponse(exchange, 404, "No symbol found at address: " + address, "SYMBOL_NOT_FOUND");
                        return;
                    }
                    
                    // Try to remove the symbol
                    // Note: Some symbols cannot be deleted (e.g., function symbols, external symbols)
                    try {
                        if (symbol.getSource() == SourceType.USER_DEFINED || 
                            symbol.getSource() == SourceType.ANALYSIS) {
                            // Delete the symbol by removing it from the symbol table
                            // We need to get all symbols at this address and remove them
                            Symbol[] symbols = symbolTable.getSymbols(address);
                            for (Symbol s : symbols) {
                                if (s.isPrimary()) {
                                    // For primary symbols, we may need to handle differently
                                    // Try to clear the name if deletion isn't possible
                                    try {
                                        s.setName("", SourceType.DEFAULT);
                                    } catch (Exception e) {
                                        // If we can't clear the name, the symbol may be undeletable
                                        throw new Exception("Cannot delete symbol: " + e.getMessage());
                                    }
                                    break;
                                }
                            }
                        } else {
                            throw new Exception("Cannot delete symbol with source type: " + symbol.getSource());
                        }
                    } catch (Exception e) {
                        sendErrorResponse(exchange, 400, "Cannot delete symbol: " + e.getMessage(), "DELETE_FAILED");
                        return;
                    }
                    
                    Map<String, Object> result = new HashMap<>();
                    result.put("message", "Symbol deleted successfully");
                    result.put("address", address.toString());
                    
                    eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange, port)
                        .success(true)
                        .result(result);
                    builder.addLink("program", "/program");
                    
                    sendJsonResponse(exchange, builder.build(), 200);
                } finally {
                    program.endTransaction(transactionID, true);
                }
            } catch (Exception e) {
                sendErrorResponse(exchange, 500, "Error deleting symbol: " + e.getMessage(), "INTERNAL_ERROR");
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
                    current = (Namespace) nsSymbol.getObject();
                    if (current == null) {
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
