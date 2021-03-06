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
import java.util.Scanner;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import capstone.Capstone;
import elf.Elf;
import elf.SectionHeader;
import elf.SectionType;
import elf.SegmentType;

/**
 * Class responsible for performing disassembly. It is only invoked once in the model.
 * Credit to the GNU Binutils library for assisting in determing the entry point and location 
 * of ELF in the symbol table.
 * The class can return information critical to displaying disassembled information in the GUI
 * see Model for information on methods invoked in disassembled to do this. 
 * @author gurjan
 *
 */
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
	private Capstone cs;
	private Set<String> conditionalCtis = new HashSet<String>();
	private TreeMap<Integer, BasicBlock> blockList;
	private int mainLoc;
	private int vtfAdjustment;
	private int rip;
	private long elapsed;

	public long getElapsed() {
		return this.elapsed;
	}

	public Disassemble(File f) throws ReadException, ElfException, MainDiscoveryException {
		long time = System.currentTimeMillis();
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

		this.vtfAdjustment = (int) elf.getProgramHeaderByType(SegmentType.LOAD).physicalAddress;
		this.entry = (int) elf.header.entryPoint - vtfAdjustment;
		this.textStart = (int) getTextSection(elf).fileOffset;
		this.textSize = (int) getTextSection(elf).size;
		this.text_bytes = Arrays.copyOfRange(data, textStart, (int) (textStart + textSize));
		this.cs = new Capstone(Capstone.CS_ARCH_X86, Capstone.CS_MODE_64);
		setSections();
		resolveSymbols(); // this only executes if function exists
		buildConditionals();
		int main = setMain();
		mainLoc = main;
		this.blockList = new TreeMap<Integer, BasicBlock>();
		this.possibleTargets.add(main);
		if (this.symtabExists) {
			for (Function ff : this.functions) {
				if (ff.getStartAddr() != 0) {
					this.possibleTargets.add(ff.getStartAddr() - vtfAdjustment);
				}
			}
			disasm(main);

		} else {
			disasm(main);
			assignParents();
			resetCallTargetParents();
			markFunctions(main);
		}

		Map<Integer, BasicBlock> splitBlockList = new TreeMap<Integer, BasicBlock>();
		splitBlocks(splitBlockList);
		updateSplitBlocks(splitBlockList);
		addLoopReferences();

		// print all basic blocks to console
		/*
		 * Iterator<BasicBlock> itit = this.blockList.values().iterator(); while
		 * (itit.hasNext()) { BasicBlock current = itit.next();
		 * //System.out.println(current.instructionsToString()); }
		 */

		long endtime = System.currentTimeMillis();
		long total = endtime - time;
		this.elapsed = total;
		System.out.println(total);
	}

	/**
	 * For blocks that reference themselves, the control flow must know this so that
	 * it can be displayed as such
	 */
	private void addLoopReferences() {
		Iterator<BasicBlock> itr = this.blockList.values().iterator();
		while (itr.hasNext()) {
			BasicBlock current = itr.next();
			if (!isConditionalCti(current.getLastInstruction()) && !isUnconditionalCti(current.getLastInstruction())) {
				if (!isReturnInstruction(current.getLastInstruction())) {
					Iterator<BasicBlock> itr2 = this.blockList.values().iterator();
					while (itr2.hasNext()) { // Iterate over the blocks to find its origin...
						BasicBlock potential = itr2.next();
						if (potential.getFirstInstruction().address == current.getLastAddress()
								+ current.getLastInstruction().size) {
							current.addLoopAddressReference(((int) potential.getFirstInstruction().address));
						}
					}
				}
			}
		}
	}

	/**
	 * Merge the values of the splitBlockList with the list of known blocks.
	 * see @splitBlocks
	 * 
	 * @param splitBlockList
	 *            to be integrated into main block list
	 */
	private void updateSplitBlocks(Map<Integer, BasicBlock> splitBlockList) {
		Iterator<BasicBlock> splitBlockIt = splitBlockList.values().iterator();
		while (splitBlockIt.hasNext()) {
			BasicBlock current = splitBlockIt.next();
			this.blockList.put(current.getFirstAddress(), current);
		}
	}

	/**
	 * See Section 6.4 of project report for detailed analysis of why this function
	 * is necessary, as well as an explanation. Split blocks which have an
	 * instruction at some point that is not the beginning which is referenced by
	 * another block ending in some jump type of instruction.
	 * 
	 * Splits the block into one block from {start of orginal block - mid block
	 * instruction} and another from {instruction after original mid block
	 * instruction - end of original block}
	 * 
	 * Updates all refrences accordingly.
	 * 
	 * @param splitBlockList
	 *            to add the newly created blocks as a result to
	 */
	private void splitBlocks(Map<Integer, BasicBlock> splitBlockList) {
		Iterator<BasicBlock> splitBlock2 = this.blockList.values().iterator();
		while (splitBlock2.hasNext()) {
			BasicBlock current = splitBlock2.next();
			if (current.getBlockSize() != 0) {
				if (current.getLastInstruction().mnemonic.equals("jmp")
						|| isConditionalCti(current.getLastInstruction())) {
					int target = getTargetAddress(current.getLastInstruction());
					if (target != -1) {
						// if block found to end in jump type instruction and the blocklist
						// doesnt contain the jump's target address the referenced instruction
						// must be part the way through some other block
						if (!this.blockList.containsKey(target)) {
							Iterator<BasicBlock> targetIt = this.blockList.values().iterator();
							// find the block containing the instruction
							while (targetIt.hasNext()) {
								BasicBlock tmp = targetIt.next();
								if (tmp.getBlockSize() != 0) {
									if (tmp.containsAddress(target)) { // -----end find block containing isntruction
										// get initial block references
										HashSet<Integer> initialAddrReferences = new HashSet<Integer>();
										HashSet<Integer> initialLoopReferences = new HashSet<Integer>();
										initialLoopReferences.addAll(tmp.getLoopAddressReferences());
										initialAddrReferences.addAll(tmp.getAddressReferenceList());
										// original instructions from first to mid block target stored in temp list
										ArrayList<Capstone.CsInsn> initialInsns = new ArrayList<Capstone.CsInsn>(
												tmp.getInstructionList().subList(0, tmp.indexOfAddress(target)));
										// original instructions after mid block target to end of block stored in list
										ArrayList<Capstone.CsInsn> targetList = new ArrayList<Capstone.CsInsn>(
												tmp.getInstructionList().subList(tmp.indexOfAddress(target),
														tmp.getInstructionList().size()));
										// block with the mist block target has its instruction list overwritten
										// with its new instructions indexing from 0-midblock target
										this.blockList.get(tmp.getFirstAddress()).overwriteInstructions(initialInsns,
												(int) targetList.get(0).address);
										// new jumpblock holds instructions midblock-end of original block
										BasicBlock jumpBlock = new BasicBlock();
										jumpBlock.setInstructionList(targetList);
										jumpBlock.setReferences(initialAddrReferences);
										jumpBlock.setLoopReferences(initialLoopReferences);
										splitBlockList.put(jumpBlock.getFirstAddress(), jumpBlock);
									}
								}
							}

						}
					}
				}
			}
		}
	}

	/**
	 * Give basic blocks parents by iterating every block's children and letting
	 * them know that their parent is the block of the current iteration
	 */
	private void assignParents() {
		Iterator<BasicBlock> blockItr = this.blockList.values().iterator();
		// give blocks parents
		while (blockItr.hasNext()) {
			BasicBlock current = blockItr.next();
			for (int children : current.getAddressReferenceList()) {
				if (this.blockList.containsKey(children)) {
					this.blockList.get(children).addParent(current.getFirstAddress());
				}
			}
		}
	}

	/**
	 * Give the target of all call instructions located in the text section no
	 * parents so that they are treated as functions by markFunctions
	 */
	private void resetCallTargetParents() {
		Iterator<BasicBlock> callToZero = this.blockList.values().iterator();
		while (callToZero.hasNext()) {
			BasicBlock current = callToZero.next();
			if (current.getLastInstruction().mnemonic.equals("call")) {
				int callAddr = getTargetAddress(current.getLastInstruction());
				if (callAddr != -1) {
					if (callAddr - this.vtfAdjustment >= textStart
							&& callAddr - this.vtfAdjustment <= textStart + textSize) {
						if (this.blockList.containsKey(callAddr)) {
							this.blockList.get(callAddr).getParents().clear();
						}
					}
				}
			}

		}
	}

	/**
	 * Mark functions with no parents as functions. create a new Function and add it
	 * to function list
	 * 
	 * @param main
	 *            address as argument so that if a function beginning with this
	 *            address is encountered it can be named 'main'
	 */
	private void markFunctions(int main) {
		Iterator<BasicBlock> testItr = this.blockList.values().iterator();
		while (testItr.hasNext()) {
			BasicBlock current = testItr.next();
			if (current.getParents().size() == 0) {
				for (Entry<Integer, BasicBlock> entry : this.blockList.tailMap(current.getFirstAddress()).entrySet()) {
					if (entry.getValue().getLastInstruction().mnemonic.equals("ret")) {
						Function ff;
						if ((current.getFirstAddress() - vtfAdjustment) == main) {
							ff = new Function("main");
						} else {
							ff = new Function(Integer.toHexString(current.getFirstAddress()));
						}
						ff.setStartAddr(current.getFirstAddress());
						ff.setEndAddr(entry.getValue().getLastInstruction().address);
						this.functions.add(ff);
						break;
					}

				}
			}
		}
	}

	/**
	 * get the location of main entry point
	 * 
	 * @return address of main
	 */
	public int getMain() {
		return this.mainLoc;
	}

	/**
	 * get all addresses visited by the disassembly procedure
	 * 
	 * @return hashset of addresses (each address is unique)
	 */
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
					// main found easily from symbol table
					return (int) funct.getStartAddr() - vtfAdjustment;
				}
			}
		} else {
			// try and discover the main for a stripped ELF
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
	 * definitely needs cleaning up
	 * 
	 * @param address
	 *            to decode the instruction at
	 * @return the current basic block of instructions
	 */
	private BasicBlock buildBlock(int address) {

		BasicBlock current = new BasicBlock();
		while (address < textStart + textSize) {
			// if address has been visited return this block
			if (this.knownAddresses.contains(address)) {
				return current;
			}
			Capstone.CsInsn instruction;
			instruction = disasmInstructionAtAddress(address, data, textStart, textSize);
			current.addInstruction(instruction); // add this instruction to block-local instruction list
			// return current block if instruction is return
			if (instruction.mnemonic.equals("ret")) {
				return current;
			}
			// if the instruction is a branch instruction perform the below logic
			if (isConditionalCti(instruction) || isUnconditionalCti(instruction)) {
				int jumpAddr = getTargetAddress(instruction) - vtfAdjustment; // target of branch
				if (jumpAddr != -1) { // if branch target is a numeric value
					// if target is in text section and hasn't been cisited
					if (jumpAddr >= textStart && jumpAddr <= textStart + textSize) {
						if (!this.knownAddresses.contains(jumpAddr)) {
							this.possibleTargets.add(jumpAddr); // add branch target to possible addresess
							if (!instruction.mnemonic.equals("call")) { // only set target as child if its not a call
								current.addAddressReference(jumpAddr + vtfAdjustment);
							}
						} else if (this.knownAddresses.contains(jumpAddr) 
								&& !this.blockList.containsKey(jumpAddr + vtfAdjustment)) {
							if (!instruction.mnemonic.equals("call")) {
								current.addAddressReference(jumpAddr + vtfAdjustment);
							}
						} else {
							if (!instruction.mnemonic.equals("call")) { 
								current.addAddressReference(jumpAddr + vtfAdjustment);
							}
						}
					} else {
						// branch target is outside cope of text section
						current.addAddressReferenceOutOfScope(jumpAddr);
					}
				}
				int continueAddr = address + instruction.size;
				// if current branch inst is not a jump target add the fallthrough address
				// to the list of potential disasm targets
				if (!instruction.mnemonic.equals("jmp")) {
					this.possibleTargets.add(continueAddr);
					current.addAddressReference(continueAddr + vtfAdjustment);
				}
				return current; // return the current block since this inst is a branch inst
			} else {
				address += instruction.size; // if not a branch instruction, disassemble at next instruction
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
			Section current = new Section(shrs.getName(), (int) shrs.virtualAddress);
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
				System.out.println(sym.getName() + "  " + sym.getAddress() + "  " + sym.getType());
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
		Capstone.CsInsn[] allInsn = this.cs.disasm(instruction_bytes, vtfAdjustment + address, 1);
		if (allInsn.length > 0) {
			this.knownAddresses.add(address);
			return allInsn[0];
		}
		return null;
	}

	/**
	 * Adds control transfer instructions to a local list of cti instructions
	 * it should be noted that the list contains all conditional cti instructions
	 */
	private void buildConditionals() {
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
	 * @throws MainDiscoveryException
	 *             if heuristic completely failed
	 */
	private int discoverMain(int entry, int textSize, byte[] data) throws MainDiscoveryException {
		ArrayList<Capstone.CsInsn> startInstructions = new ArrayList<Capstone.CsInsn>(); // list of instructions

		byte[] first_bytes = Arrays.copyOfRange(data, entry, entry + 15);
		Capstone.CsInsn[] first = cs.disasm(first_bytes, entry, 1); // first instruction disassembled
		Capstone.CsInsn instruction = first[0];
		startInstructions.add(instruction);
		int instSize = instruction.size;
		// search the next hlt instruction from offset _start by performing a linear sweep
		while (!instruction.mnemonic.equals("hlt")) { 
			this.rip = (int) (instruction.address + instruction.size);
			first_bytes = Arrays.copyOfRange(data, entry + instSize, (int) (entry + 15 + instSize));
			Capstone.CsInsn[] allInsn = cs.disasm(first_bytes, entry + instSize, 1);
			instruction = allInsn[0];
			startInstructions.add(instruction);
			instSize += instruction.size;
		}
		int index = startInstructions.size() - 1; // get index of hlt instruction
		while (!startInstructions.get(index).mnemonic.equals("call")) {
			index--; // work backwords until a call instruction has been found, said to be the call to libc_start_main
		}
		if (startInstructions.get(index).mnemonic.equals("call")) { 
			// if instruction loads some isntruction into a register, analyse its operands
			if (startInstructions.get(index - 1).mnemonic.equals("mov")
					|| startInstructions.get(index - 1).mnemonic.equals("lea")) {
				String[] operands = startInstructions.get(index - 1).opStr.split(",");
				for (String s : operands) {
					// for operands, if it is a pure numeric, the address of main is taken to be this
					if (resolveAddressFromString(s) != -1) {
						return (int) resolveAddressFromString(s) - vtfAdjustment;
					} else {
						// couldn't resolve a clean address, so get the value in the register
						// matches for the registers with definitions below
						if (s.matches(".di||.bp||.sp||.ep")) {
							// analysis the next operant 
							continue;
						} else {
							// if the address loaded is some arithmetic on the instruction point, determine the address
							// deals with the instruction mov rdi, dword ptr [rip+someaddress]
							// taking the value loaded into rdi as the address of main.
							// must perform logic converting to an arthmetically interpretable string
							if (s.contains("ip")) {
								String out = s;
								if (s.contains("[")) { 
									out = s.substring(s.indexOf("[") + 1, s.indexOf("]"));
								}
								StringBuffer buf = new StringBuffer(out);
								int start = firstIndex(buf.toString(), ".ip");
								int end = start + 3;
								// determine the value of the instruction pointer and put it in an arithmetic string
								// if some computation is performed on it
								buf.replace(start, end, Integer.toString(this.rip));  
								String halfway = buf.toString();
								int hexStrlen = 0;
								if (halfway.contains("0x")) {
									String[] tmp = halfway.split("\\s+");
									for (String st : tmp) {
										if (st.contains("0x")) {
											hexStrlen = st.length();
										}
									}
								}
								
								String ii = halfway.substring(halfway.indexOf("0x"), halfway.indexOf("0x") + hexStrlen);
								long x = Long.decode(ii);
								int d = (int) x;
								StringBuffer buf2 = new StringBuffer(halfway);
								buf2.replace(halfway.indexOf("0x"), halfway.indexOf("0x") + hexStrlen,
										Integer.toString(d));
								return evaluteQuestion(buf2.toString());

							}
							// if(out.contains(s))
						}

					}
				}

				throw new MainDiscoveryException(
						"Couldn't find main: expected address in register before call to libc_start_main");
			} else if (startInstructions.get(index - 1).mnemonic.equals("push")) {
				// main address push onto stack directly, so main found
				return (int) resolveAddressFromString(startInstructions.get(index - 1).opStr) - vtfAdjustment;
			} else {
				throw new MainDiscoveryException(
						"Couldn't find main: expected moving of main address into register before libc_start_main called,"
								+ "wasn't found at instruction proceeding call.");
			}
		} else {
			throw new MainDiscoveryException("Couldnt find main: expected call instruction before hlt in _start");
		}

	}


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

	/**
	 * Find the first index of some regex in a string
	 * @param text string to be searched for regex
	 * @param regex to be searched for 
	 * @return index into string of substring matching regex
	 */
	private int firstIndex(String text, String regex) {
		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(text);
		// Check all occurrences
		while (matcher.find()) {
			return matcher.start();
		}
		return 0;
	}

	/**
	 * Evaluates an arithmetic string. credit to 
	 * Lonely Neuron for answering question at 
	 * https://stackoverflow.com/questions/35379705/how-to-convert-a-string-containing-math-expression-into-an-integer
	 * @param question to be evaluated
	 * @return integer result of arithmetic ocmputation
	 */
	private static int evaluteQuestion(String question) {
		Scanner sc = new Scanner(question);

		// get the next number from the scanner
		int firstValue = Integer.parseInt(sc.findInLine("[0-9]*"));

		// get everything which follows and is not a number (might contain white spaces)
		String operator = sc.findInLine("[^0-9]*").trim();
		int secondValue = Integer.parseInt(sc.findInLine("[0-9]*"));
		switch (operator) {
		case "+":
			return firstValue + secondValue;
		case "-":
			return firstValue - secondValue;
		case "/":
			return firstValue / secondValue;
		case "*":
			return firstValue * secondValue;
		case "%":
			return firstValue % secondValue;
		// todo: add additional operators as needed..
		default:
			throw new RuntimeException("unknown operator: " + operator);
		}
	}

	public String getHexRepresentation(int startAddr, int endAddr, boolean spaces) {
		byte[] slice = Arrays.copyOfRange(data, startAddr, endAddr + 1);
		String hexString = "";
		if (spaces == true) {
			hexString = array2hex(slice, true);
		} else {
			hexString = array2hex(slice, false);
		}
		return hexString;
	}

	private static String array2hex(byte[] arr, boolean spaces) {
		String ret = "";
		for (int i = 0; i < arr.length; i++) {
			if (spaces == true) {
				ret += String.format("%02x ", arr[i]);
			} else {
				ret += String.format("%02x", arr[i]);
			}
			if (i % 29 == 0 && i != 0) {
				ret = ret.concat("\n");
			}
		}
		return ret;
	}

	public int getVtf() {
		return this.vtfAdjustment;
	}

}
