package program;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.logging.Logger;

import capstone.Capstone;
import capstone.Capstone.CsInsn;
import elf.Elf;
import elf.SectionHeader;

public class Disassemble {
	private Elf elf;
	private int entry;
	private byte[] data;
	private int textSize;
	private byte[] text_bytes;
	private boolean symtabExists;
	private boolean strtabExists;
	private SectionHeader symtab;
	private SectionHeader strtab;
	private ArrayList<Integer> possibleTargets = new ArrayList<Integer>();
	private HashSet<Integer> knownAddresses = new HashSet<Integer>();
	private List<Section> sections = new ArrayList<Section>();
	private ArrayList<Function> functions = new ArrayList<Function>();
	private ArrayList<Long> symbolAddresses = new ArrayList<Long>(); // Holds addresses of symbols read
	private ArrayList<SymbolEntry> symbolEntries = new ArrayList<SymbolEntry>(); // Symbol table entries

	private Capstone cs;

	private Set<String> conditionalCtis = new HashSet<String>();
	Map<Integer,BasicBlock> blockList;

	public Disassemble(File f) throws ReadException, ElfException, MainDiscoveryException {
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

		setSections();
		resolveSymbols();
		buildConditionalCtis();
		int main = setMain();
		System.out.println(main);
		this.blockList = new TreeMap<Integer,BasicBlock>();
		this.possibleTargets.add(main);
		disasm(main);
		Iterator<BasicBlock> itr = this.blockList.values().iterator();

		while (itr.hasNext()) {
			BasicBlock current = itr.next();
			// if its normal transfer instruction....
			if(!isConditionalCti(current.getLastInstruction())&&!isUnconditionalCti(current.getLastInstruction())) {
				   if(!isReturnInstruction(current.getLastInstruction())) {
					   System.out.println(current.getLastInstruction().mnemonic);
						Iterator<BasicBlock> itr2 = this.blockList.values().iterator();
						while (itr2.hasNext()) { // Iterate over the blocks to find its origin...
							BasicBlock potential = itr2.next();
							if(potential.getFirstInstruction().address==current.getLastAddress()+current.getLastInstruction().size) {
								//System.out.println("making link from "+current.getLastInstruction().address+" to "+potential.getFirstInstruction().address);
								current.addLoopAddressReference(((int) potential.getFirstInstruction().address));
							}
						}
				   }
			}
		}
		
		Iterator<BasicBlock> itr3 = this.blockList.values().iterator();
		while (itr3.hasNext()) {
			BasicBlock current = itr3.next();
			System.out.println(current.instructionsToString());
		}

		
	}
	
	public HashSet<Integer> getAssociatedAddresses(int function) {
		HashSet<Integer> blockAddresses = new HashSet<Integer>();	
		getFunctionReferences(this.blockList.get(function),blockAddresses);
		return blockAddresses;
	}
	
	private void getFunctionReferences(BasicBlock block, HashSet<Integer> blockAddresses){  
	    for (int x : block.getAddressReferenceList()) {
	    	blockAddresses.add(x);
	    	getFunctionReferences(this.blockList.get(x), blockAddresses);
	    }
	}
	
	/*
	private int getAddressReferences(int address, List<Integer> addrList) {
		if(this.blockList.get(address).getAddressReferenceList().size()==0) {
			return 0;
		} 
		for (int addr : this.blockList.get(address).getAddressReferenceList()) {
			int reference = getAddressReferences(addr,addrList);
			return reference;
		}
	}*/
	
	public Map<Integer,BasicBlock> getBasicBlocks() {
		return this.blockList;
	}

	
	private int setMain() throws MainDiscoveryException {
		if (this.symtabExists&&this.strtabExists) {
			for (Function funct : functions) {
				if (funct.getName().equals("main")) {
					return (int) funct.getStartAddr()-0x400000;
				}
			}
		} else {
			if(discoverMain(entry, textSize, data)==-1) {
				throw new MainDiscoveryException("Couldn't resolve main due to discovery heuristic failing!");
			} else {
				return discoverMain(entry, textSize, data);
			}
		}
		throw new MainDiscoveryException("Couldn't resolve main: Issue resolving from symbol table.");
	}
	
	private void disasm(int address) {
		for (int i = 0; i < this.possibleTargets.size(); i++) {
			BasicBlock current = buildBlock(this.possibleTargets.get(i));
			if(current.getBlockSize()!=0) {
				this.blockList.put(current.getFirstAddress(),current);
			}
		}
	}


	private BasicBlock buildBlock(int address) {
		BasicBlock current = new BasicBlock();
		while (address < entry + textSize) {
			if (this.knownAddresses.contains(address)) {
				return current;
			}
			Capstone.CsInsn instruction;
			instruction = disasmInstructionAtAddress(address, data, entry, textSize);
			//System.out.printf("0x%x:\t%s\t%s\n", (int) instruction.address, instruction.mnemonic, instruction.opStr);
			current.addInstruction(instruction);

			if (instruction.mnemonic.equals("ret")) {
				return current;
			}

			if (isConditionalCti(instruction) || isUnconditionalCti(instruction)) {
				// BEGIN DEALING WITH JUMP TARGET
				int jumpAddr = getTargetAddress(instruction)-0x400000; // determine CTI destination
				if (jumpAddr != -1) { // if dest can be reached
					if (jumpAddr >= entry && jumpAddr <= entry + textSize) { // if within text section
						if (!this.knownAddresses.contains(jumpAddr)) {
							this.possibleTargets.add(jumpAddr); // one target to disassemble at
							current.addAddressReference(jumpAddr+0x400000);
						} else {
							current.addAddressReference(jumpAddr+0x400000);
						}
					} else {
						current.addAddressReferenceOutOfScope(jumpAddr);
						//current.addAddressReference(address+0x400000);
					}
				}
				// END DEALIGN WITH JUMP TARGET, BEGIN DEALING WITH FALLTHROUGH
				int continueAddr = address + instruction.size; // diasm at enxt inst address
				if (!instruction.mnemonic.equals("jmp")) {
					this.possibleTargets.add(continueAddr); // add next address to possible target
					current.addAddressReference(continueAddr+0x400000);
				} else {
					current.addAddressReference(continueAddr+0x400000);
				}
				// END DEALING WITH FALLTHROUGH
				return current;
			} else { // its not a CTI so disasm next
				address += instruction.size;
			}
		}
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
	
	private int resolveAddressFromString(String string) {
		try {
			long address = Long.decode(string.trim());
			return (int) address;
		} catch (NumberFormatException e) {
			return -1;
		}
	}

	/**
	 * Disassemble instruction at some address. Adds the address to a set of known addresses.
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
		Capstone.CsInsn[] allInsn = this.cs.disasm(instruction_bytes, 0x400000 + address, 1);
		if (allInsn.length > 0) {
			this.knownAddresses.add(address);
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
	
	private int discoverMain(int entry, int textSize, byte[] data) {
		ArrayList<Capstone.CsInsn> startInstructions = new ArrayList<Capstone.CsInsn>();
		text_bytes = Arrays.copyOfRange(data, entry, (int) (entry + 15));
		Capstone.CsInsn[] first = cs.disasm(text_bytes, entry, 1);
		Capstone.CsInsn instruction = first[0];
		startInstructions.add(instruction);
		int InstSize = instruction.size;
		while (!instruction.mnemonic.equals("hlt")) {
			text_bytes = Arrays.copyOfRange(data, entry + InstSize, (int) (entry + 100));
			Capstone.CsInsn[] allInsn = cs.disasm(text_bytes, entry + InstSize, 1);
			startInstructions.add(allInsn[0]);
			instruction = allInsn[0];
			InstSize += instruction.size;
		}
		int index = startInstructions.size()-2;
		while (!startInstructions.get(index).mnemonic.equals("call")) {
			index-=1;
		}
		if(startInstructions.get(index).mnemonic.equals("call")) {
			if(startInstructions.get(index-1).mnemonic.equals("mov")) {
				System.out.println(startInstructions.get(index-1).opStr);
				String[] operands = startInstructions.get(index-1).opStr.split(",");
				for (String s : operands) {
					if (resolveAddressFromString(s)!=-1) {
						return (int) resolveAddressFromString(s)-0x400000;
					} 
				}
				return -1;
			} else if(startInstructions.get(index-1).mnemonic.equals("push")) {
				return (int) resolveAddressFromString(startInstructions.get(index-1).opStr)-0x400000;
			} else {
				return -1;
			}
		}
		return -1;
	}
	
	/* peerform a single instruction linear sweep for testing purposes
	private void singleInstLinearSweep(int entry, int textSize, byte[] data, Capstone cs) {
		int InstSize = 0;
		while (entry + InstSize < entry + textSize) {
			text_bytes = Arrays.copyOfRange(data, entry + InstSize, (int) (entry + textSize));
			Capstone.CsInsn[] allInsn = cs.disasm(text_bytes, entry + InstSize, 1);
			InstSize += allInsn[0].size;
			System.out.printf("0x%x:\t%s\t%s\n", allInsn[0].address, allInsn[0].mnemonic, allInsn[0].opStr);
		}
	}*/

	private SectionHeader getTextSection(Elf elf) {
		for (SectionHeader shrs : elf.sectionHeaders) {
			if (shrs.getName().equals(".text")) {
				return shrs;
			}
		}
		return elf.sectionHeaders[1];
	}

}
