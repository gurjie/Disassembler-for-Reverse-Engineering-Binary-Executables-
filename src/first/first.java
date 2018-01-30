package first;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

import capstone.Capstone;
import elf.Elf;
import elf.SectionHeader;

/**
 * This program's overall operation is quite simple. See the program's activity
 * diagram in the report for a basic idea! 
 * 
 * Initially, I tried to disassemble executables from their 0th byte, 
 * thinking that would do something. 
 * On top of this, I was not even aware that file format mattered.
 * I had read plenty of articles on disassembly, but completely skipped things like file formats.
 * 
 * The main objective of this program was to produce some disassembly, performing
 * a linear sweep on some given executable.
 * 
 * To do this, the ELF's entry point must be determined, so that code can be disassembled further,
 * This is done with the assistance of GNU binutils' ELF parse library.
 * 
 * Once the entry point has been determined, disassembly can begin. 
 * But first, I thought it would be nice to interpret the Symbol table
 * in the ELF if it were present, so SymbolEntry was written.
 * 
 * The sequence of bytes to disassemble is then passed to Capstone to disassemble.
 * 
 * @author Gurjan
 *
 */
public class first {
	static String filePath; // set this as desired
	static byte[] textBytes = null; // holds .text section to disassemble
	static byte[] symtabBytes = null; // bytes of the symbol table to work with
	static byte[] sliceBytes; // one-entry-sized slices of the symbol table to pass to SymbolEntry,
	// so that the class can interpret an entry (if symtab exists)
	static byte[] strtab_bytes; // string table holding function names referenced by symtab
	static ArrayList<Long> symbolAddresses = new ArrayList<Long>(); // Holds addresses of symbols read
	static ArrayList<SymbolEntry> symbolEntries = new ArrayList<SymbolEntry>(); // Symbol table entries
	static SectionHeader symtab;
	static String pathName;

	/**
	 * (utility) Sporadically used for interpreting the executables
	 * @param arr array to convert to hex
	 * @return hexadecimal string representative of the byte array
	 */
    private static String array2hex(byte[] arr) {
        String ret = "";
        for (int i=0 ;i<arr.length; i++)
            ret += String.format("0x%02x ", arr[i]);
        return ret;
    }
    
    /**
     * Used sometimes, retrieves the text section of an ELF, using the ELF parser
     * @param elf ELF to be read
     * @return SectionHeader object holding the .text section
     */
    private static SectionHeader getTextSection(Elf elf) {
    	for(SectionHeader shrs : elf.sectionHeaders) {
    		if(shrs.getName().equals(".text")) {
    			return shrs;
    		}
    	}
    	return elf.sectionHeaders[1];
    }
    
    /**
     * Used to retrieve .strtab of an ELF, using the ELF parser
     * @param elf ELF to be read
     * @return SectionHeader object holding the .strtab section
     * @throws Exception 
     */
    private static SectionHeader getStrTab(Elf elf) throws Exception {
    	for(SectionHeader shrs : elf.sectionHeaders) {
    		if(shrs.getName().equals(".strtab")) {
    			return shrs;
    		}
    	}
    	throw new Exception("FAILED TO RESOLVE THE STRING TABLE!");
    }
    
    /**
     * Get the symbol table, providing the ELF has not been stripped. 
     * @param elf to be read
     * @return Section header table entry representing .symtab
     * @throws Exception thrown if the symbol table doesn't exist
     */
    private static SectionHeader getSymbolTable(Elf elf) throws Exception {
    	for(SectionHeader shrs : elf.sectionHeaders) {
    		if(shrs.getName().equals(".symtab")) {
    			return shrs;
    		}
    	}
    	throw new Exception("FAILED TO RESOLVE THE SYMBOL TABLE: ELF MAY BE STRIPPED!");
    }
    
	public static void main(String[] args) throws IOException {
		handleInput();
	    Path path = Paths.get(pathName);
		File f = new File(pathName);
	    byte[] data = Files.readAllBytes(path); //convert the executable to bytes
		Elf elf = new Elf(f);
		int entry = (int) (elf.header.entryPoint-0x400000); // Crucially, we have the entry point! It should represent 
		// file offset, so format it accordingly
		try {
			symtab = getSymbolTable(elf); // get the symbol table from the ELF parser
			SectionHeader strtab = getStrTab(elf); // get the string table holding symbol names
			// Load the two tables' size and file offset information
			int symtab_size = (int) symtab.size; 
			int symtab_offset = (int) symtab.fileOffset;
			int strtab_size = (int) strtab.size;
			int strtab_offset = (int) strtab.fileOffset;
			// (for below) There is a less memory intensive way of doing this, but at the moment,
			// slices of the entire elf are taken corresponding to .symtab and .strtab 
			symtabBytes = Arrays.copyOfRange(data, symtab_offset, symtab_offset+symtab_size);
			strtab_bytes = Arrays.copyOfRange(data, strtab_offset, strtab_offset+strtab_size);
			
			// A .symtab entry has 24 bytes. Parse it accordingly
			for(int i = 0; i<symtab_size; i+=24) {
				sliceBytes = Arrays.copyOfRange(symtabBytes, i, i+24); // represents a .symtab entry
				SymbolEntry current = new SymbolEntry(sliceBytes,strtab_bytes); // current entry object created
				symbolEntries.add(current); // Added to the symbol table entry list
				symbolAddresses.add(current.getAddress()); //  Addresses of any symbols added
			}
			
			textBytes = Arrays.copyOfRange(data, entry, data.length-1); // defines bytes to disassembly
			
			Capstone cs = new Capstone(Capstone.CS_ARCH_X86, Capstone.CS_MODE_64);
			Capstone.CsInsn[] allInsn = cs.disasm(textBytes, entry+0x400000);	 
			// print every instruction in the disassembled set
			for (int iv=0; iv<allInsn.length; iv++) {
				if(symbolAddresses.contains(allInsn[iv].address)) {
					for(SymbolEntry s:symbolEntries) {
						if(allInsn[iv].address==s.getAddress()) {
							System.out.println("\n<"+s.getName()+">");
						}
					}
				}
			    System.out.printf("0x%x:\t%s\t%s", allInsn[iv].address, allInsn[iv].mnemonic, allInsn[iv].opStr);
			    System.out.print("          "+allInsn[iv].operands+"\n");
			}
		} catch (Exception e1) {
			// just disassemble as normal if there's no symbol entry table
			textBytes = Arrays.copyOfRange(data, entry, entry+(int)getTextSection(elf).size);
			Capstone cs = new Capstone(Capstone.CS_ARCH_X86, Capstone.CS_MODE_64);
			Capstone.CsInsn[] allInsn = cs.disasm(textBytes, entry+0x400000);	 
			for (int iv=0; iv<allInsn.length; iv++) {
			    System.out.printf("0x%x:\t%s\t%s\n", allInsn[iv].address, allInsn[iv].mnemonic, allInsn[iv].opStr);
			}
		}
	}
	
	private static void handleInput() {
		System.out.println("Specify a path to an ELF file");
		Scanner p = new Scanner(System.in);
		pathName = p.nextLine();
	}
}
