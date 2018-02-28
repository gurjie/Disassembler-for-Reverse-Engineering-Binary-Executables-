package program;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import capstone.Capstone;
import elf.Elf;
import elf.SectionHeader;

public class Disassemble {

	private boolean symtabExists;
	private boolean strtabExists;
	private SectionHeader symtab;
	private SectionHeader strtab;
	private Elf elf;
	private byte[] data;
	private byte[] text_bytes;
	private int textSize;
	private int entry;
	private ArrayList<Function> functions = new ArrayList<Function>();
	//private HashSet<Integer> knownAddresses = new HashSet<Integer>();
	ArrayList<Long> symbolAddresses = new ArrayList<Long>(); // Holds addresses of symbols read
	ArrayList<SymbolEntry> symbolEntries = new ArrayList<SymbolEntry>(); // Symbol table entries
	List<Section> sections = new ArrayList<Section>();
	Capstone cs;

	public Disassemble(File f) throws ReadException, ElfException {
		try {
			this.data = Files.readAllBytes(f.toPath());
		} catch (IOException e) {
			throw new ReadException("Error reading selected file into byte array.");
		}
		try {
			this.elf = new Elf(f);
		} catch (IOException e) {
			throw new ElfException(e.getMessage() + "\nPerhaps select an ELF 64 bit file");
		}

		this.entry = (int) getTextSection(elf).fileOffset;
		this.textSize = (int) getTextSection(elf).size;
		this.text_bytes = Arrays.copyOfRange(data, entry, (int) (entry + textSize));
		this.cs = new Capstone(Capstone.CS_ARCH_X86, Capstone.CS_MODE_64);
		Capstone.CsInsn inst = disasmInstructionAtAddress(entry, data, cs, entry, textSize);
		System.out.printf("0x%x:\t%s\t%s\n", inst.address, inst.mnemonic, inst.opStr);
		System.out.println(inst.size);

		setSections();
		resolveSymbols(); 
		//disasm(cs,entry,)
		// Load the two tables' size and file offset information
		// Capstone cs = new Capstone(Capstone.CS_ARCH_X86, Capstone.CS_MODE_64);
		// singleInstLinearSweep(entry, textSize, data, cs);
		// discoverFunctions(entry, textSize, data, cs);
	}

	public void diasm(long startAddress) {

	}

	public List<Function> getFunctions() {
		return this.functions;
	}

	private void setSections() {
		for (SectionHeader shrs : this.elf.sectionHeaders) {
			checkForSymtab(shrs);
			checkForStrTab(shrs);
			Section current = new Section(shrs.getName());
			this.sections.add(current);
		}
	}

	private void resolveSymbols() {
		if (this.symtabExists) {
			int symtab_size = (int) this.symtab.size;
			int symtab_offset = (int) this.symtab.fileOffset;
			int strtab_size = (int) this.strtab.size;
			int strtab_offset = (int) this.strtab.fileOffset;
			byte[] symtabBytes = Arrays.copyOfRange(data, symtab_offset, symtab_offset + symtab_size);
			byte[] strtab_bytes = Arrays.copyOfRange(data, strtab_offset, strtab_offset + strtab_size);
			// A .symtab entry has 24 bytes. Parse it accordingly
			for (int i = 0; i < symtab_size; i += 24) {
				byte[] sliceBytes = Arrays.copyOfRange(symtabBytes, i, i + 24); // represents a .symtab entry
				SymbolEntry current = new SymbolEntry(sliceBytes, strtab_bytes); // current entry object created
				this.symbolEntries.add(current); // Added to the symbol table entry list
				this.symbolAddresses.add(current.getAddress()); // Addresses of any symbols added
			}
			for (SymbolEntry sym : this.symbolEntries) {
				addFunctionFromSymtab(sym);
			}			
		}
	}

	public List<Section> getSections() {
		return this.sections;
	}
	
	
	private void addFunctionFromSymtab(SymbolEntry sym) {
		if (sym.getType().equals("STT_FUNCT")) {
			Function current = new Function(sym.getName());
			current.setStartAddr(sym.getAddress());
			current.setEndAddr(sym.getAddress() + sym.getSize());
			if (sym.getAddress()==0) {
				this.functions.add(0, current);
			} else {
				this.functions.add(current);
			}
		}
	}

	private void checkForSymtab(SectionHeader sectionHeader) {
		if (sectionHeader.getName().equals(".symtab")) {
			this.symtabExists = true;
			this.symtab = sectionHeader;
		}
	}

	private void checkForStrTab(SectionHeader sectionHeader) {
		if (sectionHeader.getName().equals(".strtab")) {
			this.strtabExists = true;
			this.strtab = sectionHeader;
		}
	}

	public boolean symTabExists() {
		return this.symtabExists;
	}

	/*
	 * private void discoverFunctions(int entry, int textSize, byte[] data, Capstone
	 * cs) { int address = entry; while (address<entry+textSize) { Capstone.CsInsn
	 * instruction = disasmInstructionAtAddress(address,data,cs,entry,textSize,1);
	 * if (instruction!=null) { if (instruction.mnemonic.equals("push")) {
	 * //System.out.println(instruction.insnName()); Capstone.CsInsn
	 * secondInstruction = disasm2AtAddress(address,data,cs,entry,textSize); if
	 * (secondInstruction.mnemonic.equals("mov")) {
	 * if(instruction.opStr.equals("rbp")) { if
	 * (secondInstruction.opStr.equals("rbp, rsp")) { Function function = new
	 * Function();
	 * 
	 * } } }
	 * 
	 * } } }
	 * 
	 * address+=1;
	 * 
	 * 
	 * }
	 */

	/**
	 * 
	 * @param address
	 *            address in the byte data representing the file to disassemble at
	 * @param data
	 *            - bytes representing the executable
	 * @param cs
	 *            capstone instance
	 * @param entry
	 *            entry point of the elf
	 * @param textSize
	 *            size of the text section in the elf
	 * @param count
	 *            number of instructions to be disassmbled
	 */
	private Capstone.CsInsn disasmInstructionAtAddress(int address, byte[] data, Capstone cs, int entry,
			long textSize) {
		byte[] instruction_bytes = Arrays.copyOfRange(data, (int) address, (int) address + 15);
		Capstone.CsInsn[] allInsn = cs.disasm(instruction_bytes, 0x0 + address, 1);
		if (allInsn.length > 0) {
			// System.out.printf("0x%x:\t%s\t%s\n", allInsn[0].address, allInsn[0].mnemonic,
			// allInsn[0].opStr);
			return allInsn[0];
		}
		return null;
	}

	/*
	 * private static Capstone.CsInsn disasm2AtAddress(int address, byte[] data,
	 * Capstone cs, int entry, long textSize) { byte[] instruction_bytes =
	 * Arrays.copyOfRange(data, (int) address, (int) address+15); Capstone.CsInsn[]
	 * allInsn = cs.disasm(instruction_bytes,0x0+address,2); if(allInsn.length>0) {
	 * //System.out.printf("0x%x:\t%s\t%s\n", allInsn[0].address,
	 * allInsn[0].mnemonic, allInsn[0].opStr); return allInsn[1]; } return null; }
	 */

	private void singleInstLinearSweep(int entry, int textSize, byte[] data, Capstone cs) {
		int InstSize = 0;
		while (entry + InstSize < entry + textSize) {
			text_bytes = Arrays.copyOfRange(data, entry + InstSize, (int) (entry + textSize));
			Capstone.CsInsn[] allInsn = cs.disasm(text_bytes, entry + InstSize, 1);
			InstSize += allInsn[0].size;
			System.out.printf("0x%x:\t%s\t%s\n", allInsn[0].address, allInsn[0].mnemonic, allInsn[0].opStr);
		}
	}

	private SectionHeader getTextSection(Elf elf) {
		for (SectionHeader shrs : elf.sectionHeaders) {
			if (shrs.getName().equals(".text")) {
				return shrs;
			}
		}
		return elf.sectionHeaders[1];
	}

}
