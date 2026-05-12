// Ghidra Post-Script: dump decompiled pseudo-C for the top-N functions
// by xref count, plus the symbol table and string cross-references.
//
// Invoked by analyzeHeadless via -postScript. Input arguments:
//   args[0] : output JSON path
//   args[1] : top_n function count (default 25)
//
// Output: a single JSON file containing:
//   {
//     "program": { "name": "...", "language": "..." },
//     "functions": [
//        { "name": "...", "address": "...", "xref_count": N,
//          "pseudocode": "...", "params": [...], "signature": "..." }
//     ],
//     "symbols":  [ { "name": "...", "type": "...", "address": "..." } ],
//     "strings":  [ { "value": "...", "address": "...", "xrefs": [...] } ]
//   }
//
// Ghidra script entry point is a class extending GhidraScript.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;

import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class DumpPseudoC extends GhidraScript {

    private static final int DEFAULT_TOP_N = 25;
    private static final int MAX_STRINGS = 200;
    private static final int MAX_SYMBOLS = 500;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("DumpPseudoC: output path argument required");
            return;
        }
        String outputPath = args[0];
        int topN = DEFAULT_TOP_N;
        if (args.length >= 2) {
            try { topN = Integer.parseInt(args[1]); } catch (NumberFormatException ignored) {}
        }

        Program program = currentProgram;
        if (program == null) {
            printerr("DumpPseudoC: no currentProgram");
            return;
        }

        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(program);

            List<FunctionRanked> ranked = rankFunctions(program);
            StringBuilder json = new StringBuilder();
            json.append("{");

            // program meta
            json.append("\"program\":{");
            json.append("\"name\":").append(quote(program.getName())).append(',');
            json.append("\"language\":").append(quote(program.getLanguage().toString()));
            json.append("},");

            // functions
            json.append("\"functions\":[");
            int emitted = 0;
            for (int i = 0; i < Math.min(topN, ranked.size()); i++) {
                if (emitted > 0) json.append(',');
                FunctionRanked fr = ranked.get(i);
                Function f = fr.fn;
                String pseudoC = decompile(decomp, f);
                json.append('{');
                json.append("\"name\":").append(quote(f.getName())).append(',');
                json.append("\"address\":").append(quote(f.getEntryPoint().toString())).append(',');
                json.append("\"xref_count\":").append(fr.xrefs).append(',');
                json.append("\"signature\":").append(quote(f.getPrototypeString(false, false))).append(',');
                json.append("\"pseudocode\":").append(quote(truncate(pseudoC, 8000)));
                json.append('}');
                emitted += 1;
            }
            json.append("],");

            // symbols
            json.append("\"symbols\":[");
            SymbolTable st = program.getSymbolTable();
            SymbolIterator symIter = st.getAllSymbols(false);
            int symCount = 0;
            boolean firstSym = true;
            while (symIter.hasNext() && symCount < MAX_SYMBOLS) {
                Symbol s = symIter.next();
                if (s == null) continue;
                if (firstSym) firstSym = false;
                else json.append(',');
                json.append('{');
                json.append("\"name\":").append(quote(s.getName())).append(',');
                json.append("\"type\":").append(quote(s.getSymbolType().toString())).append(',');
                json.append("\"address\":").append(quote(String.valueOf(s.getAddress())));
                json.append('}');
                symCount += 1;
            }
            json.append("],");

            // strings
            json.append("\"strings\":[");
            Listing listing = program.getListing();
            int strCount = 0;
            boolean firstStr = true;
            for (Data data : listing.getDefinedData(true)) {
                try {
                    String val = null;
                    if (data.hasStringValue()) {
                        StringDataInstance sdi = StringDataInstance.getStringDataInstance(data);
                        if (sdi != null) val = sdi.getStringValue();
                    }
                    if (val == null || val.isEmpty() || val.length() < 6) continue;
                    if (firstStr) firstStr = false;
                    else json.append(',');
                    json.append('{');
                    json.append("\"value\":").append(quote(truncate(val, 200))).append(',');
                    json.append("\"address\":").append(quote(String.valueOf(data.getAddress()))).append(',');
                    json.append("\"xrefs\":[");
                    ReferenceIterator refs = data.getReferenceIteratorTo();
                    boolean firstRef = true;
                    int refCount = 0;
                    while (refs.hasNext() && refCount < 5) {
                        Reference r = refs.next();
                        if (firstRef) firstRef = false;
                        else json.append(',');
                        json.append(quote(String.valueOf(r.getFromAddress())));
                        refCount += 1;
                    }
                    json.append("]}");
                    strCount += 1;
                    if (strCount >= MAX_STRINGS) break;
                } catch (Exception ex) {
                    // Skip malformed strings
                }
            }
            json.append("]");

            json.append("}");

            try (FileWriter fw = new FileWriter(outputPath)) {
                fw.write(json.toString());
            }
            println("DumpPseudoC: wrote " + outputPath + " (" + emitted + " functions)");
        } finally {
            decomp.dispose();
        }
    }

    private String decompile(DecompInterface decomp, Function f) {
        try {
            DecompileResults res = decomp.decompileFunction(f, 30, TaskMonitor.DUMMY);
            if (res != null && res.decompileCompleted()) {
                return res.getDecompiledFunction().getC();
            }
            return "// decompilation failed: " + (res == null ? "null" : res.getErrorMessage());
        } catch (Exception ex) {
            return "// decompilation exception: " + ex.getMessage();
        }
    }

    private List<FunctionRanked> rankFunctions(Program program) {
        List<FunctionRanked> list = new ArrayList<>();
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f.isExternal() || f.isThunk()) continue;
            int count = 0;
            try {
                ReferenceIterator refs = program.getReferenceManager().getReferencesTo(f.getEntryPoint());
                while (refs.hasNext()) {
                    refs.next();
                    count += 1;
                    if (count > 10000) break;  // cap
                }
            } catch (Exception ex) { /* ignore */ }
            list.add(new FunctionRanked(f, count));
        }
        list.sort(Comparator.comparingInt((FunctionRanked a) -> a.xrefs).reversed());
        return list;
    }

    private static class FunctionRanked {
        final Function fn;
        final int xrefs;
        FunctionRanked(Function fn, int xrefs) { this.fn = fn; this.xrefs = xrefs; }
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        if (s.length() <= max) return s;
        return s.substring(0, max) + "...[truncated]";
    }

    private static String quote(String s) {
        if (s == null) return "\"\"";
        StringBuilder sb = new StringBuilder(s.length() + 8);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        sb.append('"');
        return sb.toString();
    }
}
