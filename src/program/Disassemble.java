package program;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
	private HashSet<Integer> knownAddresses = new HashSet<Integer>();
	private ArrayList<Long> symbolAddresses = new ArrayList<Long>(); // Holds addresses of symbols read
	private ArrayList<SymbolEntry> symbolEntries = new ArrayList<SymbolEntry>(); // Symbol table entries
	private List<Section> sections = new ArrayList<Section>();
	private Capstone cs;
	private ArrayList<Capstone.CsInsn> failedDisassemblyTargets = new ArrayList<Capstone.CsInsn>();
	private Set<String> conditionalCtis = new HashSet<String>();
	ArrayList<BasicBlock> blockList;

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
		// Capstone.CsInsn inst = disasmInstructionAtAddress(entry, data, cs, entry,
		// textSize);
		// System.out.printf("0x%x:\t%s\t%s\n", inst.address, inst.mnemonic,
		// inst.opStr);
		// System.out.println(inst.size);

		setSections();
		resolveSymbols();
		buildConditionalCtis();
		
		int main = 0;
		for (Function funct : functions) {
			if (funct.getName().equals("main")) {
				main = (int) funct.getStartAddr() - 0x400000;

			}
		}
		System.out.println(this.entry);

		blockList = new ArrayList<BasicBlock>();
		disasm(main);
		Collections.sort(blockList,new Comparator<BasicBlock>() {
			@Override
			public int compare(BasicBlock o1, BasicBlock o2) {
				return (o1.getFirst() - o2.getFirst());
			}
			
		});
		
		for(BasicBlock block : blockList) {				
			block.printInstructions();
		}
		

		// disasm(cs,entry,)
		// Load the two tables' size and file offset information
		// Capstone cs = new Capstone(Capstone.CS_ARCH_X86, Capstone.CS_MODE_64);
		// ingleInstLinearSweep(entry, textSize, data, cs);
		// discoverFunctions(entry, textSize, data, cs);
	}

	public BasicBlock disasm(int address) {
		BasicBlock current = new BasicBlock();
		this.blockList.add(current);
		if (this.knownAddresses.contains(address)) {
			return current;
		}
		do {
			Capstone.CsInsn instruction;
			instruction = disasmInstructionAtAddress(address, data, entry, textSize);
			//System.out.printf("0x%x:\t%s\t%s\n",(int) instruction.address, instruction.mnemonic, instruction.opStr);
			current.addInstruction(instruction);
			/*if (isReturnInstruction(instruction)) {
				return current;
			} else if (isUnconditionalCti(instruction)) {
				int destinationAddr = getTargetAddress(instruction);
				if (destinationAddr != -1) {
					if (destinationAddr < entry || destinationAddr > entry+textSize) {
						int continueAddr = address + instruction.size;
						return current;
					}  else {
						current.addAddressReference(getTargetAddress(instruction));
						return disasm(getTargetAddress(instruction));
					}
				} else {
					current.addPtrReference(instruction.opStr);
				}

			}*/ if (isConditionalCti(instruction)||isUnconditionalCti(instruction)) {
				ArrayList<Integer> possibleTargets = new ArrayList<Integer>();
				int jumpAddr = getTargetAddress(instruction); // determine CTI destination
				if (jumpAddr != -1) { // if dest can be reached
					if (jumpAddr > entry && jumpAddr < entry+textSize) { // if within text section
						current.addAddressReference(jumpAddr); // ignore for now
						possibleTargets.add(jumpAddr); // one target to disassemble at
					} else {
						address += instruction.size; // if its outside of scope of text disasm next
						continue;
						
					}
				} else {
					current.addPtrReference(instruction.opStr);
				}
				int continueAddr = address + instruction.size; // diasm at enxt inst address
				possibleTargets.add(continueAddr); // add next address to possible target
				current.addAddressReference(continueAddr); // ignore for now
				for (int addr : possibleTargets) { // for all possible disassemble targets
					if (this.knownAddresses.contains(addr)) { // if the address hasn't been disasm already
						continue; // skip to the next disasm target
					}
					return disasm(addr); // disasm at first address (recursive)
				}
			} else { // its not a CTI so disasm next
				address += instruction.size;
			}

		} while (address <= entry + textSize);
		return current;
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
			if (sym.getAddress() == 0) {
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

	private boolean isUnconditionalCti(Capstone.CsInsn instruction) {
		if (!instruction.mnemonic.matches("jmp|call|int")) {
			return false;
		}
		return true;
	}

	private boolean isReturnInstruction(Capstone.CsInsn instruction) {
		if (!instruction.mnemonic.equals("ret")) {
			return false;
		}
		return true;
	}

	private boolean isConditionalCti(Capstone.CsInsn instruction) {
		if (this.conditionalCtis.contains(instruction.mnemonic)) {
			return true;
		}
		return false;

	}

	private int getTargetAddress(Capstone.CsInsn instruction) {
		try {
			long address = Long.decode(instruction.opStr.trim());
			return (int) address;
		} catch (NumberFormatException e) {
			return -1;
		}
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
	 * @throws AddressOutOfRangeException
	 *             thrown if the address to disassemble is outside of the text
	 *             section
	 * 
	 */
	private Capstone.CsInsn disasmInstructionAtAddress(int address, byte[] data, int entry, long textSize) {
		byte[] instruction_bytes = Arrays.copyOfRange(data, (int) address, (int) address + 15);
		Capstone.CsInsn[] allInsn = this.cs.disasm(instruction_bytes, 0x0 + address, 1);
		if (allInsn.length > 0) {
			this.knownAddresses.add(address);
	
			// System.out.printf("0x%x:\t%s\t%s\n", allInsn[0].address, allInsn[0].mnemonic,
			// allInsn[0].opStr);
			return allInsn[0];
		}
		return null;
	}

	private void buildConditionalCtis() {
		this.conditionalCtis.add("ja");
		this.conditionalCtis.add("jnbe");
		this.conditionalCtis.add("jae");
		this.conditionalCtis.add("jnb");
		this.conditionalCtis.add("jb");
		this.conditionalCtis.add("jnae");
		this.conditionalCtis.add("jbe");
		this.conditionalCtis.add("jna");
		this.conditionalCtis.add("jc");
		this.conditionalCtis.add("je");
		this.conditionalCtis.add("jz");
		this.conditionalCtis.add("jnc");
		this.conditionalCtis.add("jne");
		this.conditionalCtis.add("jnz");
		this.conditionalCtis.add("jnp");
		this.conditionalCtis.add("jpo");
		this.conditionalCtis.add("jp");
		this.conditionalCtis.add("jpe");
		this.conditionalCtis.add("jg");
		this.conditionalCtis.add("jnle");
		this.conditionalCtis.add("jge");
		this.conditionalCtis.add("jnl");
		this.conditionalCtis.add("jl");
		this.conditionalCtis.add("jnge");
		this.conditionalCtis.add("jle");
		this.conditionalCtis.add("jng");
		this.conditionalCtis.add("jno");
		this.conditionalCtis.add("jns");
		this.conditionalCtis.add("jo");
		this.conditionalCtis.add("js");
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
