package program;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import capstone.Capstone;
import capstone.Capstone.CsInsn;

public class BasicBlock {
	private ArrayList<Capstone.CsInsn> instructionList;
	private HashSet<Integer> addressReferences = new HashSet<Integer>();
	private HashSet<Integer> loopAddressReferences = new HashSet<Integer>();
	private HashSet<Integer> outOfScopeReferences = new HashSet<Integer>();
	private HashSet<Integer> parents = new HashSet<Integer>();
	private ArrayList<String> ptrReferences = new ArrayList<String>();
	private int startAddress;
	private int endAddress;
	private boolean isFunction;

	/**
	 * Create a new basic block, initialise its instruction block
	 */
	public BasicBlock() {
		instructionList = new ArrayList<Capstone.CsInsn>();
	}

	/**
	 * Give this basic block a parent
	 * 
	 * @param address
	 *            address of its parent block
	 */
	public void addParent(int address) {
		this.parents.add(address);
	}

	/**
	 * Get list of block's parents
	 * 
	 * @return list containing parents
	 */
	public HashSet<Integer> getParents() {
		return this.parents;
	}

	/**
	 * Amount of instructions represented by a block
	 * 
	 * @return list of instructions representing the block
	 */
	public int getInstructionCount() {
		return this.instructionList.size();
	}

	/**
	 * Gets the list of instructions held in this block
	 * 
	 * @return list of instructions help by the block
	 */
	public ArrayList<Capstone.CsInsn> getInstructionList() {
		return this.instructionList;
	}

	/**
	 * Get the size of a given block
	 * 
	 * @return number of instructions held in a block
	 */
	public int getBlockSize() {
		return this.instructionList.size();
	}

	/**
	 * @return first address represented by an instruction block
	 */
	public int getFirstAddress() {
		return (int) this.instructionList.get(0).address;
	}

	/**
	 * 
	 * @return last address in an instruction block
	 */
	public int getLastAddress() {
		return (int) this.instructionList.get(this.instructionList.size() - 1).address;
	}

	/**
	 * @return last instruciton in an instruction block
	 */
	public Capstone.CsInsn getLastInstruction() {
		return this.instructionList.get(this.instructionList.size() - 1);
	}

	/**
	 * @return first instruction of a basic block
	 */
	public Capstone.CsInsn getFirstInstruction() {
		return this.instructionList.get(0);
	}

	/**
	 * Tells us if this block contains an address
	 * 
	 * @param address
	 *            whos presence is to be checked
	 * @return true if block contains address, false otherwise
	 */
	public boolean containsAddress(int address) {
		if (address <= this.endAddress && address >= this.startAddress) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * The index into the set of instructions of a certain address
	 * 
	 * @param address
	 *            to have its index returned
	 * @return index into the block, return -1 if teh instruction isn't in the block
	 */
	public int indexOfAddress(int address) {
		for (Capstone.CsInsn inst : this.instructionList) {
			if (inst.address == address) {
				return this.instructionList.indexOf(inst);
			}
		}
		return 0;
	}

	/**
	 * Overwrite an instruction list held by a block, by replacing its instruction
	 * list New address references must be given, due to nature of when this is
	 * actually called
	 * 
	 * @param newList
	 *            to overwrite current instruction list
	 * @param newReference
	 *            to be added to address reference list of this block
	 */
	public void overwriteInstructions(ArrayList<CsInsn> newList, int newReference) {
		this.instructionList = newList;
		this.addressReferences.clear();
		this.addressReferences.add(newReference);
	}

	/**
	 * give a block an instruction list
	 * 
	 * @param newList
	 *            to be set as the block's instruction list
	 */
	public void setInstructionList(ArrayList<CsInsn> newList) {
		this.instructionList = newList;
		this.startAddress = (int) newList.get(0).address;
		this.startAddress = (int) newList.get(newList.size() - 1).address;
	}

	/**
	 * Give the block an address reference list. Used during split block procedure.
	 * 
	 * @param initialReferences
	 */
	public void setReferences(HashSet<Integer> initialReferences) {
		this.addressReferences = initialReferences;
	}

	/**
	 * Gives block loop reference list
	 * 
	 * @param initialLoopReferences
	 *            to be set as loop references of the block
	 */
	public void setLoopReferences(HashSet<Integer> initialLoopReferences) {
		this.loopAddressReferences = initialLoopReferences;
	}

	/**
	 * Construct a string of instructions to be displayed in a really clearl format
	 * 
	 * @return string representing a block's instructions
	 */
	public String instructionsToString() {
		String instStr = "";
		// instStr = instStr.concat("-------START-------\n");
		for (Capstone.CsInsn instruction : instructionList) {
			instStr = instStr.concat(String.format("0x%x:\t%s\t %s\n", (int) instruction.address, instruction.mnemonic,
					instruction.opStr));
			// System.out.printf("0x%x:\t%s\t%s\n", (int) instruction.address,
			// instruction.mnemonic, instruction.opStr);
		}
		// instStr = instStr.concat("-------END-------\n");
		instStr = instStr.concat("references: ");
		for (int reference : addressReferences) {
			instStr = instStr.concat(("0x" + Integer.toHexString(reference) + "; "));
		}
		for (int reference : loopAddressReferences) {
			instStr = instStr.concat(("0x" + Integer.toHexString(reference) + "; "));
		}
		instStr = instStr.concat("\n");
		return instStr;
	}

	/**
	 * Add instruction to a block
	 * 
	 * @param instruction
	 *            to be appended to the end of a block's isntruction list
	 */
	public void addInstruction(Capstone.CsInsn instruction) {
		if (this.instructionList.isEmpty()) {
			this.startAddress = (int) instruction.address;
			this.endAddress = (int) instruction.address;
		} else {
			this.endAddress = (int) instruction.address;
		}
		this.instructionList.add(instruction);
	}

	/**
	 * Add an address referenced to a block
	 * 
	 * @param reference
	 *            address referenced
	 */
	public void addAddressReference(int reference) {
		this.addressReferences.add(reference);
	}

	/**
	 * Deprecated, but adds an address references for a block when the address
	 * reference cannot be reached
	 * 
	 * @param reference
	 *            to be added
	 */
	public void addAddressReferenceOutOfScope(int reference) {
		this.outOfScopeReferences.add(reference);
	}

	/**
	 * Give this block a loop address reference if it references an ancestor of a
	 * parent block
	 * 
	 * @param reference
	 *            to be added to the block
	 */
	public void addLoopAddressReference(int reference) {
		if (!this.addressReferences.contains(reference)) {
			this.loopAddressReferences.add(reference);
		}
	}

	// never used
	public void addPtrReference(String reference) {
		this.ptrReferences.add(reference);
	}

	/**
	 * get the list of instructions referenced by a function
	 * 
	 * @return hashset containing all instruction referenced
	 */
	public HashSet<Integer> getAddressReferenceList() {
		return this.addressReferences;
	}

	/**
	 * get the lost of ancestor blocks referenced by a block
	 * 
	 * @return list of loop references
	 */
	public HashSet<Integer> getLoopAddressReferences() {
		return this.loopAddressReferences;
	}

	/**
	 * is the instruction list of this block empty?
	 * 
	 * @return true if it is, false otherwise
	 */
	public boolean isEmpty() {
		return this.instructionList.isEmpty();
	}

	/**
	 * How many parents does this block have?
	 * 
	 * @return how many parents it has
	 */
	public int getParentCount() {
		return this.parents.size();
	}
}
