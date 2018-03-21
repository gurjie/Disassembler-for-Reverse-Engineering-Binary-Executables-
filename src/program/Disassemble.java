package program;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;
import capstone.Capstone;
import elf.Elf;
import elf.SectionHeader;

public class Disassemble {
	private Elf elf;
	private int textStart;
	private byte[] data;
	private int textSize;
	private int entry;
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
	private HashSet<Integer> midBlockTargets = new HashSet<Integer>();
	private Capstone cs;
	private Set<String> conditionalCtis = new HashSet<String>();
	private TreeMap<Integer, BasicBlock> blockList;
	private int mainLoc;

	public String getHexRepresentation(int startAddr, int endAddr, boolean spaces) {
		byte[] slice = Arrays.copyOfRange(data, startAddr, endAddr+1);
		String hexString = "";
		if (spaces==true) {
			hexString = array2hex(slice, true);

		} else {
			hexString = array2hex(slice, false);

		}
		return hexString;
	}
    
    private static String array2hex(byte[] arr, boolean spaces) {
        String ret = "";
        for (int i=0;i<arr.length; i++) {
        	if(spaces==true) {
        		ret += String.format("%02x ", arr[i]);
        	} else {
        		ret += String.format("%02x", arr[i]);
        	}
        	if(i%40==0&&i!=0) {
        		ret = ret.concat("\n");
        	}
        }
        return ret;
    }
	
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
		// System.out.println(elf.header);
		
		this.entry = (int) elf.header.entryPoint-0x400000;
		this.textStart = (int) getTextSection(elf).fileOffset;
		this.textSize = (int) getTextSection(elf).size;
		this.text_bytes = Arrays.copyOfRange(data, textStart, (int) (textStart + textSize));
		this.cs = new Capstone(Capstone.CS_ARCH_X86, Capstone.CS_MODE_64);

		setSections();
		resolveSymbols(); // this only executes if function exists
		buildConditionalCtis();
		int main = setMain();
		mainLoc = main;
		this.blockList = new TreeMap<Integer, BasicBlock>();
		this.possibleTargets.add(main);
		if (this.symtabExists) {
			for (Function ff : this.functions) {
				if (ff.getStartAddr() != 0) {
					this.possibleTargets.add(ff.getStartAddr() - 0x400000);
				}
			}
			disasm(main);
		} else {
			disasm(main);
			Iterator<BasicBlock> blockItr = this.blockList.values().iterator();
			
			// give blocks parents
			while (blockItr.hasNext()) {
				BasicBlock current = blockItr.next();
				for(int children : current.getAddressReferenceList()) {
					if(this.blockList.containsKey(children)) {
						this.blockList.get(children).addParent(current.getFirstAddress());
					} 
				}
			}
			
			// set blocks with 0 parents as a function
			Iterator<BasicBlock> testItr = this.blockList.values().iterator();
			while (testItr.hasNext()) {
				BasicBlock current = testItr.next();
				if(current.getParents().size()==0) {
					for(Entry<Integer, BasicBlock> entry : this.blockList.tailMap(current.getFirstAddress()).entrySet()) {
						if(entry.getValue().getLastInstruction().mnemonic.equals("ret")) {
							Function ff;
							if((current.getFirstAddress()-0x400000)==main) {
								ff = new Function("main");
							} else {
								ff = new Function(Integer.toHexString(current.getFirstAddress()));

							}
							ff.setStartAddr(current.getFirstAddress());
							ff.setEndAddr(entry.getValue().getLastInstruction().address);
							this.functions.add(ff);
							ff.setAssociatedAddresses(this.blockList);
							break;
						}
					}
					//System.out.println(Integer.toHexString(current.getFirstAddress())+ " has no parents. Function?" );
				}
				//System.out.println(current.instructionsToString());
			}
			
			//System.out.println("there are "+knownCallTargets.size()+" unique call targets. sounds fishy?");
			// find functions
			/*
			Iterator<BasicBlock> itr4 = this.blockList.values().iterator();
			while (itr4.hasNext()) {
				BasicBlock current = itr4.next();
				if (current.getInstructionList().get(0).mnemonic.equals("push")
						&& current.getInstructionList().get(1).mnemonic.equals("mov")) {
					if (current.getInstructionList().get(0).opStr.matches(".bp")) {
						if (current.getInstructionList().get(1).opStr.matches(".bp, .sp")) {
							Function function = new Function("0x" + Integer.toHexString((current.getFirstAddress())));
							function.setStartAddr(current.getFirstAddress());
							for(Entry<Integer, BasicBlock> entry : this.blockList.tailMap(current.getFirstAddress()).entrySet()) {
								if(entry.getValue().getLastInstruction().mnemonic.equals("ret")) {
									function.setEndAddr(entry.getValue().getLastInstruction().address);
									break;
								}
							}
							boolean contains = false;
							for(Function ff:this.functions) {
								if(ff.getStartAddr()==current.getFirstAddress()) {
									contains = true;
								}
							}
							if(contains==false) {
								this.functions.add(function);
								System.out.println("added");
							}
						}
					}
				}

			}*/
		}

		Iterator<BasicBlock> splitBlock2 = this.blockList.values().iterator();
		Map<Integer, BasicBlock> splitBlockList = new TreeMap<Integer, BasicBlock>();

		while (splitBlock2.hasNext()) {
			BasicBlock current = splitBlock2.next();
			if(current.getBlockSize()!=0) {
			if(current.getLastInstruction().mnemonic.equals("jmp")||isConditionalCti(current.getLastInstruction())) {
				int target = getTargetAddress(current.getLastInstruction());
				if(target!=-1) {
					if(!this.blockList.containsKey(target)) {
						Iterator<BasicBlock> targetIt = this.blockList.values().iterator();
						while (targetIt.hasNext()) {
							BasicBlock tmp = targetIt.next();
							if(tmp.getBlockSize()!=0) {
							if(tmp.containsAddress(target)) {
								HashSet<Integer> initialAddrReferences = new HashSet<Integer>();
								HashSet<Integer> initialLoopReferences = new HashSet<Integer>();
								initialLoopReferences.addAll(tmp.getLoopAddressReferences());
								initialAddrReferences.addAll(tmp.getAddressReferenceList());
								ArrayList<Capstone.CsInsn> initialInsns = new ArrayList<Capstone.CsInsn>(
										tmp.getInstructionList().subList(0, tmp.indexOfAddress(target)));
								ArrayList<Capstone.CsInsn> targetList = new ArrayList<Capstone.CsInsn>(tmp.getInstructionList()
										.subList(tmp.indexOfAddress(target), tmp.getInstructionList().size()));
								this.blockList.get(tmp.getFirstAddress()).overwriteInstructions(initialInsns,
										(int) targetList.get(0).address);
								BasicBlock jumpBlock = new BasicBlock(); // to hold instructions at and after split
								jumpBlock.setInstructionList(targetList);
								jumpBlock.setReferences(initialAddrReferences);
								jumpBlock.setLoopReferences(initialLoopReferences);
								splitBlockList.put(jumpBlock.getFirstAddress(), jumpBlock);
							}
						}}
						
					}
				}
			}
			}
		}

		Iterator<BasicBlock> splitBlockIt = splitBlockList.values().iterator();
		while (splitBlockIt.hasNext()) {
			BasicBlock current = splitBlockIt.next();
			this.blockList.put(current.getFirstAddress(), current);
			//System.out.println("/x//////"+current.instructionsToString());
		}

		Iterator<BasicBlock> itr = this.blockList.values().iterator();
		while (itr.hasNext()) {
			BasicBlock current = itr.next();
			// if its normal transfer instruction....
			if (!isConditionalCti(current.getLastInstruction()) && !isUnconditionalCti(current.getLastInstruction())) {
				if (!isReturnInstruction(current.getLastInstruction())) {
					Iterator<BasicBlock> itr2 = this.blockList.values().iterator();
					while (itr2.hasNext()) { // Iterate over the blocks to find its origin...
						BasicBlock potential = itr2.next();
						if (potential.getFirstInstruction().address == current.getLastAddress()
								+ current.getLastInstruction().size) {
							// System.out.println("making link from "+current.getLastInstruction().address+"
							// to "+potential.getFirstInstruction().address);
							current.addLoopAddressReference(((int) potential.getFirstInstruction().address));
						}
					}
				}
			}
		}

		/*
		Iterator<BasicBlock> itr3 = this.blockList.values().iterator();
		while (itr3.hasNext()) {
			BasicBlock current = itr3.next();
			System.out.println(current.instructionsToString());
		}*/

	}

	public int getMain() {
		return this.mainLoc;
	}
	
	public HashSet<Integer> getKnownAddresses() {
		return this.knownAddresses;
	}

	/**
	 * get the list of instruction blocks
	 * 
	 * @return list of instruction blocks that have been disassembled
	 */
	public Map<Integer, BasicBlock> getBasicBlocks() {
		return this.blockList;
	}

	/**
	 * Find the main function
	 * 
	 * @return the address of the main function
	 * @throws MainDiscoveryException
	 *             if the main function couldn't be found
	 */
	private int setMain() throws MainDiscoveryException {
		if (this.symtabExists && this.strtabExists) {
			for (Function funct : functions) {
				if (funct.getName().equals("main")) {
					return (int) funct.getStartAddr() - 0x400000;
				}
			}
		} else {
			int discovered = discoverMain(entry, textSize, data);
			if (discovered == -1) {
				throw new MainDiscoveryException("Couldn't resolve main due to discovery heuristic failing!");
			} else {
				return discovered;
			}
		}
		throw new MainDiscoveryException("Couldn't resolve main: Issue resolving from symbol table.");
	}

	/**
	 * For all possible target disassembly addresses in the list, build a BasicBlock
	 * block by calling buildBlock, which will build a basic block of instructions
	 * and add it the list of disassembled blocks if the block is not empty. Can
	 * disassemble at all valid targets of the input address
	 * 
	 * @param address
	 *            beginning address; should be 'main'
	 */
	private void disasm(int address) {
		for (int i = 0; i < this.possibleTargets.size(); i++) {
			BasicBlock current = buildBlock(this.possibleTargets.get(i));
			if(current.getInstructionList().size()!=0&&current.getFirstAddress()==4205752) {
				System.out.println("adaggdagadgdgad");
			}
			if (current.getBlockSize() != 0) {
				this.blockList.put(current.getFirstAddress(), current);
			}
		}
	}

	/**
	 * - Takes an address to start at as an argument, builds the first basic block -
	 * while address is in .text, decode instruction at the input address, and then
	 * disassembles at addres+sizeof(instruction) - if the current instruction is a
	 * conditional control transfer instruction, and its target is a clearly defined
	 * address within the scope of the .text section, 1) if the address is not
	 * known, disassemble at this address, 2) else if the address is known but is
	 * not that start of a basic block, add to a list of blocks to be split (as the
	 * jump is somewhere in some existing basic block) and add reference to the
	 * block 3) else add a reference to the target address from this basic block,
	 * but don't disassemble there, as that has already been done.
	 * 
	 * - Then begin dealing with the follow through instruction of the CTI: if it's
	 * not a jump instruction, the next instruction after this (conditional) CTI
	 * must also be a target of the CTI. i.e. jz 0x4002860 has 0x4002860 and also
	 * jz.address+sizeof(jz) as targets. - Add this target address as an address
	 * referenced by the current block, and disassemble at the target. - This means
	 * that the end of the current block has reached, and control is being
	 * transferred: return current block
	 * 
	 * - In the case that the current instruction is not a CTI or return, simply
	 * disassemble at the next address.
	 * 
	 * @param address
	 *            to decode the instruction at
	 * @return the current basic block of instructions
	 */
	private BasicBlock buildBlock(int address) {

		BasicBlock current = new BasicBlock();
		while (address < textStart + textSize) {
			if (this.knownAddresses.contains(address)) {
				return current;
			}
			Capstone.CsInsn instruction;
			instruction = disasmInstructionAtAddress(address, data, textStart, textSize);
			current.addInstruction(instruction);
			/*
			if(current.getFirstAddress()==4205746) {
				System.out.println(x);
			}*/
			/*
			if (address == 4205752 - 0x400000) {
				System.out.println(current.getFirstAddress());
				System.out.println("first instruction of cb8 is "+instruction.mnemonic);
				System.out.println(current.getBlockSize());
			}*/

			if (instruction.mnemonic.equals("ret")) {
				return current;
			}

			if (isConditionalCti(instruction) || isUnconditionalCti(instruction)) {
				int jumpAddr = getTargetAddress(instruction) - 0x400000;
				if (jumpAddr != -1) {
					if (jumpAddr >= textStart && jumpAddr <= textStart + textSize) {
						if (!this.knownAddresses.contains(jumpAddr)) {
							this.possibleTargets.add(jumpAddr);
							if(!instruction.mnemonic.equals("call")) {
								current.addAddressReference(jumpAddr + 0x400000);
							} 
						} else if (this.knownAddresses.contains(jumpAddr)
								&& !this.blockList.containsKey(jumpAddr + 0x400000)) {
							this.midBlockTargets.add(jumpAddr);
							if(!instruction.mnemonic.equals("call")) {
								current.addAddressReference(jumpAddr + 0x400000);
							}
						} else {
							if(!instruction.mnemonic.equals("call")) {
								current.addAddressReference(jumpAddr + 0x400000);
							}						}
					} else {
						current.addAddressReferenceOutOfScope(jumpAddr);
					}
				}
				int continueAddr = address + instruction.size;
				if (!instruction.mnemonic.equals("jmp")) {
					this.possibleTargets.add(continueAddr);
					current.addAddressReference(continueAddr + 0x400000);
				}
				return current;
			} else {
				address += instruction.size;
			}
		}
		return current;
	}

	/**
	 * get the list of functions known in the ELF
	 * 
	 * @return list of functions
	 */
	public List<Function> getFunctions() {
		return this.functions;
	}

	/**
	 * sets the sections in the ELF
	 */
	private void setSections() {
		for (SectionHeader shrs : this.elf.sectionHeaders) {
			checkForSymtab(shrs);
			checkForStrTab(shrs);
			Section current = new Section(shrs.getName());
			this.sections.add(current);
		}
	}

	/**
	 * Parse the symbol table and resolve all symbols in the ELF, then take the
	 * useful ones (functions) and build a list of functions
	 */
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

	/**
	 * Get sections in the ELF
	 * 
	 * @return list of sections in ELF
	 */
	public List<Section> getSections() {
		return this.sections;
	}

	/**
	 * If an entry in the symbol table has the type property corresponding to what
	 * is defined as a function, add it to the list of known program functions
	 * 
	 * @param sym
	 *            symbol entry to be checked whether it is a function or not
	 */
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

	/**
	 * Find out whether this section header passed in is the symbol table
	 * 
	 * @param sectionHeader
	 *            to be parsed
	 */
	private void checkForSymtab(SectionHeader sectionHeader) {
		if (sectionHeader.getName().equals(".symtab")) {
			this.symtabExists = true;
			this.symtab = sectionHeader;
		}
	}

	/**
	 * Find out whether this section header passed in is the string table
	 * 
	 * @param sectionHeader
	 *            to be parsed
	 */
	private void checkForStrTab(SectionHeader sectionHeader) {
		if (sectionHeader.getName().equals(".strtab")) {
			this.strtabExists = true;
			this.strtab = sectionHeader;
		}
	}

	/**
	 * Does the symtab exist?
	 * 
	 * @return true if symtabExists field is true, false otherwise
	 */
	public boolean symTabExists() {
		return this.symtabExists;
	}

	/**
	 * is the instruction an unconditional control transfer instruction?
	 * 
	 * @param instruction
	 *            to be parsed
	 * @return true if UnconCti, false otherwise
	 */
	private boolean isUnconditionalCti(Capstone.CsInsn instruction) {
		if (!instruction.mnemonic.matches("jmp|call|int")) {
			return false;
		}
		return true;
	}

	/**
	 * is the instruction a return instruction?
	 * 
	 * @param instruction
	 *            to be parsed
	 * @return true if return, false if otherwise
	 */
	private boolean isReturnInstruction(Capstone.CsInsn instruction) {
		if (!instruction.mnemonic.equals("ret")) {
			return false;
		}
		return true;
	}

	/**
	 * is the instruction passed in a conditional control transfer? i.e. jne, jz,
	 * jnz etc...proeprty: has a target and fallthrough instruction
	 * 
	 * @param instruction
	 *            to be parsed
	 * @return true if conditional cti, false otherwise
	 */
	private boolean isConditionalCti(Capstone.CsInsn instruction) {
		if (this.conditionalCtis.contains(instruction.mnemonic)) {
			return true;
		}
		return false;

	}

	/**
	 * get target address of an instruction with a clear target address
	 * 
	 * @param instruction
	 *            to be parsed
	 * @return the operand representing the target address
	 */
	private int getTargetAddress(Capstone.CsInsn instruction) {
		try {
			long address = Long.decode(instruction.opStr.trim());
			return (int) address;
		} catch (NumberFormatException e) {
			return -1;
		}
	}

	/**
	 * Converts a string representing an numerical address to integer
	 * 
	 * @param string
	 *            to be converted
	 * @return the integer representation, -1 if unsuccessful (i.e. string not
	 *         numerical)
	 */
	private int resolveAddressFromString(String string) {
		try {
			long address = Long.decode(string.trim());
			return (int) address;
		} catch (NumberFormatException e) {
			return -1;
		}
	}

	/**
	 * Disassemble instruction at some address. Adds the address to a set of known
	 * addresses.
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
		Capstone.CsInsn[] allInsn = this.cs.disasm(instruction_bytes, 0x400000 + address, 1);
		if (allInsn.length > 0) {
			this.knownAddresses.add(address);
			return allInsn[0];
		}
		return null;
	}

	/**
	 * Adds control transfer instructions to a local list of cti instructions
	 */
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

	/**
	 * Quite experimental but can find the 'main' function on basic stripped ELFs
	 * 
	 * @param entry
	 *            entry point of the program (beggining of _start)
	 * @param textSize
	 *            size of the .text section
	 * @param data:
	 *            ELF file represented as a sequence of bytes
	 * @return the address of the main function
	 * @throws MainDiscoveryException  if heuristic completely failed
	 */
	private int discoverMain(int entry, int textSize, byte[] data) throws MainDiscoveryException {
		ArrayList<Capstone.CsInsn> startInstructions = new ArrayList<Capstone.CsInsn>(); // list of instructions
		byte[] first_bytes = Arrays.copyOfRange(data, entry, entry + 15);
		Capstone.CsInsn[] first = cs.disasm(first_bytes, entry, 1); // first instruction disassembled
		Capstone.CsInsn instruction = first[0];
		startInstructions.add(instruction);
		int instSize = instruction.size;
		while (!instruction.mnemonic.equals("hlt")) {
			// disassemble until hlt reached
			first_bytes = Arrays.copyOfRange(data, entry+instSize, (int) (entry + 15+instSize));
			Capstone.CsInsn[] allInsn = cs.disasm(first_bytes, entry + instSize, 1);
			instruction = allInsn[0];
			startInstructions.add(instruction);
			instSize += instruction.size;
		}
		int index = startInstructions.size() - 1;
		while (!startInstructions.get(index).mnemonic.equals("call")) {
			index--;
		}
		if (startInstructions.get(index).mnemonic.equals("call")) {
			if (startInstructions.get(index - 1).mnemonic.equals("mov")) {
				String[] operands = startInstructions.get(index - 1).opStr.split(",");
				for (String s : operands) {
					if (resolveAddressFromString(s) != -1) {
						return (int) resolveAddressFromString(s) - 0x400000;
					} 
				}
				throw new MainDiscoveryException("Couldn't find main: expected address in register before call to libc_start_main");
			} else if (startInstructions.get(index - 1).mnemonic.equals("push")) {
				return (int) resolveAddressFromString(startInstructions.get(index - 1).opStr) - 0x400000;
			} else {
				throw new MainDiscoveryException("Couldn't find main: expected moving of main address into register before libc_start_main called,"
						+ "wasn't found at instruction proceeding call.");
			}
		} else {
			throw new MainDiscoveryException("Couldnt find main: expected call instruction before hlt in _start");
		}
	
	}

	// perform a single instruction linear sweep for testing purposes
	/*
	 * private void singleInstLinearSweep(int entry, int textSize, byte[] data,
	 * Capstone cs, int start, int end, int address) { int InstSize = 0; while
	 * (address < end&&address>start) { text_bytes = Arrays.copyOfRange(data,
	 * address, (int) (address + textSize)); Capstone.CsInsn[] allInsn =
	 * cs.disasm(text_bytes, entry + InstSize, 1); InstSize += allInsn[0].size;
	 * System.out.printf("0x%x:\t%s\t%s\n", allInsn[0].address, allInsn[0].mnemonic,
	 * allInsn[0].opStr); } }
	 */

	/**
	 * Get the text section for the ELF passes as argument
	 * 
	 * @param elf
	 *            file with text seciton to be extracted
	 * @return SectionHeader with name .text
	 */
	private SectionHeader getTextSection(Elf elf) {
		for (SectionHeader shrs : elf.sectionHeaders) {
			if (shrs.getName().equals(".text")) {
				return shrs;
			}
		}
		return elf.sectionHeaders[1];
	}

}
