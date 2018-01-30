package first;

public class SymbolType {
    private final int ID;
    private final String description;
    
    public static final SymbolType STT_NOTYPE = new SymbolType(0, "Symbol type unspecified");
    public static final SymbolType STT_OBJECT = new SymbolType(1, "Symbol associated with data object(variable/array,etc)");
    public static final SymbolType STT_FUNC = new SymbolType(2, "Symbol associated with function/executable code");
    public static final SymbolType STT_SECTION = new SymbolType(3, "Symbol associated with section");
    public static final SymbolType STT_FILE = new SymbolType(4, "GOOGLE");
    public static final SymbolType STT_COMMON = new SymbolType(5, "labels unitialized common block. treated as STT_OBJECT");
    public static final SymbolType STT_TLS = new SymbolType(6, "//outofscope//");
    public static final SymbolType STT_LOOS = new SymbolType(10, "values here are reserved for OS specific semantics");
    public static final SymbolType STT_HIOS = new SymbolType(12, "values here are reserved for OS specific semantics");
    public static final SymbolType STT_LOPROC = new SymbolType(13, "values here are reserved for processor specific semantics");
    public static final SymbolType STT_HIPROC = new SymbolType(15, "values here are reserved for processor specific semantics");
 
    private static final SymbolType[] TYPES = {STT_NOTYPE,STT_OBJECT,STT_FUNC,STT_SECTION,
    		STT_FILE,STT_COMMON,STT_TLS,STT_LOOS,STT_HIOS,STT_LOPROC,STT_HIPROC};
    
    
    public SymbolType(int ID, String description) {
        this.ID = ID;
        this.description = description;
    }
    
    public String description() {
    	return this.description;
    }
    
   
}
