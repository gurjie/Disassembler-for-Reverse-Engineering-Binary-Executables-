package first;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

import capstone.Capstone;
import capstone.Capstone.CsInsn;
import elf.Elf;
import elf.SectionHeader;


public class single_disasm {
	static String filePath;// /home/gurjan/sample
	static byte[] text_bytes = null;
	static byte[] symtab_bytes = null;
	static byte[] slice_bytes;
	static byte[] strtab_bytes;
	static byte[] symbol_bytes;
	static byte[] rela_plt_bytes;
	static byte[] dynsym_bytes;
	static byte[] dynstr_bytes;
	static byte[] main_bytes_onwards;
	static int relEntrySize = 0;
	static ArrayList<Long> symbol_addresses = new ArrayList<Long>();
	static ArrayList<SymbolEntry> symbol_entries = new ArrayList<SymbolEntry>();

    private static String array2hex(byte[] arr) {
        String ret = "";
        for (int i=0 ;i<arr.length; i++)
            ret += String.format("0x%02x ", arr[i]);
        return ret;
    }
    
    private static SectionHeader getTextSection(Elf elf) {
    	for(SectionHeader shrs : elf.sectionHeaders) {
    		if(shrs.getName().equals(".text")) {
    			return shrs;
    		}
    	}
    	return elf.sectionHeaders[1];
    }
    
    private static SectionHeader getStrTab(Elf elf) {
    	for(SectionHeader shrs : elf.sectionHeaders) {
    		if(shrs.getName().equals(".strtab")) {
    			return shrs;
    		}
    	}
    	return elf.sectionHeaders[1];
    }
    
    
    private static SectionHeader getSymbolTable(Elf elf) throws Exception {
    	for(SectionHeader shrs : elf.sectionHeaders) {
    		if(shrs.getName().equals(".symtab")) {
    			return shrs;
    		}
    	}
    	throw new Exception("FAILED TO RESOLVE THE SYMBOL TABLE: ELF MAY BE STRIPPED!");
    }
    
    private static SectionHeader getPlt(Elf elf) throws Exception {
    	for(SectionHeader shrs : elf.sectionHeaders) {
    		if(shrs.getName().equals(".rela.plt")) {
    			relEntrySize = 24;
    			return shrs;
    		}
    		if (shrs.getName().equals("rel.plt")) {
    			relEntrySize = 20;
    			return shrs;
    		}
    	}
    	throw new Exception("FAILED TO RESOLVE THE SYMBOL TABLE: ELF MAY BE STRIPPED!");
    }
    
    private static SectionHeader getDynsym(Elf elf) throws Exception {
    	for(SectionHeader shrs : elf.sectionHeaders) {
    		if(shrs.getName().equals(".dynsym")) {
    			return shrs;
    		}
    	}
    	throw new Exception("FAILED TO RESOLVE THE SYMBOL TABLE: ELF MAY BE STRIPPED!");
    }
    
    private static SectionHeader getDynStr(Elf elf) throws Exception {
    	for(SectionHeader shrs : elf.sectionHeaders) {
    		if(shrs.getName().equals(".dynstr")) {
    			return shrs;
    		}
    	}
    	throw new Exception("FAILED TO RESOLVE THE SYMBOL TABLE: ELF MAY BE STRIPPED!");
    }
    
    private static void printSections(Elf elf) throws Exception {
    	for(SectionHeader shrs : elf.sectionHeaders) {
    		if(shrs.getName()!=null) {
    			System.out.println(shrs.getName());
    		}
    	}
    	throw new Exception("FAILED TO RESOLVE THE SYMBOL TABLE: ELF MAY BE STRIPPED!");
    }
    
	public static void main(String[] args) throws Exception {
	    Path path = Paths.get("maze");
		File f = new File("maze");
	    byte[] data = Files.readAllBytes(path); //convert the executable to bytes
		Elf elf = new Elf(f);
		int entry = (int) (elf.header.entryPoint-0x400000);
		SectionHeader symtab;
		SectionHeader relaPlt;
		SectionHeader dynsym;
		SectionHeader dynstr;
		try {
			dynsym = getDynsym(elf);
			symtab = getSymbolTable(elf);
			relaPlt = getPlt(elf);
			dynstr = getDynStr(elf);
			SectionHeader strtab = getStrTab(elf);
			int dynstr_offset = (int) dynstr.fileOffset;
			int dynstr_size = (int) dynstr.size;
			int reloc_offset = (int) relaPlt.fileOffset;
			int reloc_size = (int) relaPlt.size;
			int dynsym_offset = (int) dynsym.fileOffset;
			int dynsym_size = (int) dynsym.size;
			int symtab_size = (int) symtab.size;
			int symtab_offset = (int) symtab.fileOffset;
			int strtab_size = (int) strtab.size;
			int strtab_offset = (int) strtab.fileOffset;
			long textSize = getTextSection(elf).size;
			
			
			symtab_bytes = Arrays.copyOfRange(data, symtab_offset, symtab_offset+symtab_size);
			strtab_bytes = Arrays.copyOfRange(data, strtab_offset, strtab_offset+strtab_size);
			for(int i = 0; i<symtab_size; i+=24) {
				slice_bytes = Arrays.copyOfRange(symtab_bytes, i, i+24);
				SymbolEntry current = new SymbolEntry(slice_bytes,strtab_bytes);
				symbol_entries.add(current);
				symbol_addresses.add(current.getAddress());
			}
			text_bytes = Arrays.copyOfRange(data, entry, (int) (entry+textSize));

			
			rela_plt_bytes = Arrays.copyOfRange(data, reloc_offset, reloc_offset+reloc_size);
			dynsym_bytes = Arrays.copyOfRange(data, dynsym_offset, dynsym_offset+dynsym_size);
			dynstr_bytes = Arrays.copyOfRange(data, dynstr_offset, dynstr_offset+dynstr_size);
			text_bytes = Arrays.copyOfRange(data, entry, (int) (entry+textSize));
			long address = reloc_offset;
			//printSections(elf);
			/*
			for(int i = 0; i<reloc_size; i+=relEntrySize) {
				slice_bytes = Arrays.copyOfRange(rela_plt_bytes, i, i+relEntrySize);
				RelocEntry current = new RelocEntry(slice_bytes,dynsym_bytes,dynstr_bytes);
				System.out.print(current.name+"\t");
				System.out.println(current.getIndex());
				address+=relEntrySize-1;
			}*/
			Capstone cs = new Capstone(Capstone.CS_ARCH_X86, Capstone.CS_MODE_64);

			//main_bytes_onwards = Arrays.copyOfRange(data, mainAddr, (int) (mainAddr+(entry+textSize-mainAddr)));

			int InstSize = 0;
			
			
			while(entry+InstSize<entry+textSize) {
				text_bytes = Arrays.copyOfRange(data, entry+InstSize, (int) (entry+textSize));
				Capstone.CsInsn[] allInsn = cs.disasm(text_bytes, entry+InstSize+0x400000,1);
				InstSize += allInsn[0].size;
			    System.out.printf("0x%x:\t%s\t%s\n", allInsn[0].address, allInsn[0].mnemonic, allInsn[0].opStr);
			}
			
			/* CODE FOR SINGLE INST DSIASSEMBLY WOOOO
			int InstSize = 0;
			while(entry+InstSize<entry+textSize) {
				text_bytes = Arrays.copyOfRange(data, entry+InstSize, (int) (entry+textSize));
				Capstone.CsInsn[] allInsn = cs.disasm(text_bytes, entry+InstSize+0x400000,1);
				InstSize += allInsn[0].size;
			    System.out.printf("0x%x:\t%s\t%s\n", allInsn[0].address, allInsn[0].mnemonic, allInsn[0].opStr);
			}*/

		} catch (Exception e1) {
			e1.printStackTrace();
			text_bytes = Arrays.copyOfRange(data, entry, data.length-1);
			e1.getMessage();
			Capstone cs = new Capstone(Capstone.CS_ARCH_X86, Capstone.CS_MODE_64);
			Capstone.CsInsn[] allInsn = cs.disasm(text_bytes, entry+0x400000);	 
			for (int iv=0; iv<allInsn.length; iv++) {
			    System.out.printf("0x%x:\t%s\t%s\n", allInsn[iv].address, allInsn[iv].mnemonic, allInsn[iv].opStr);
			}
		}
		

	}
	
}
