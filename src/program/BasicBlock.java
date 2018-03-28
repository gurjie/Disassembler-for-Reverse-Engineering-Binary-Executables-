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

	public BasicBlock() {
		instructionList = new ArrayList<Capstone.CsInsn>();
	}
	
	public void addParent(int address) {
		this.parents.add(address);
	}
	
	public HashSet<Integer> getParents(){
		return this.parents;
	}
	
	public int getInstructionCount() {
		return this.instructionList.size();
	}
	
	public ArrayList<Capstone.CsInsn> getInstructionList() {
		return this.instructionList;
	}
	
	public int getBlockSize() {
		return this.instructionList.size();
	}

	public int getFirstAddress() {
		return (int) this.instructionList.get(0).address;
	}
	
	public int getLastAddress() {
		return (int) this.instructionList.get(this.instructionList.size()-1).address;
	}
	
	public Capstone.CsInsn getLastInstruction() {
		return this.instructionList.get(this.instructionList.size()-1);
	}
	
	public Capstone.CsInsn getFirstInstruction() {
		return this.instructionList.get(0);
	}
	
	public boolean containsAddress(int address) {
		if(address<=this.endAddress&&address>=this.startAddress) {
			return true;
		} else {
			return false;
		}
	}
	
	public int indexOfAddress(int address) {
		for(Capstone.CsInsn inst : this.instructionList) {
			if(inst.address==address) {
				return this.instructionList.indexOf(inst);
			}
		}
		return 0;
	}
	
	public void overwriteInstructions(ArrayList<CsInsn> newList,int newReference) {
		this.instructionList = newList;
		this.addressReferences.clear();
		this.addressReferences.add(newReference);
	}
	
	public void setInstructionList(ArrayList<CsInsn> newList) {
		this.instructionList = newList;
		this.startAddress = (int) newList.get(0).address;
		this.startAddress = (int) newList.get(newList.size()-1).address;
	}
	
	public void setReferences(HashSet<Integer> initialReferences) {
		this.addressReferences = initialReferences;
	}
	
	public void setLoopReferences(HashSet<Integer> initialLoopReferences) {
		this.loopAddressReferences = initialLoopReferences;
	}
	

	public String instructionsToString() {
		String instStr = "";
		//instStr = instStr.concat("-------START-------\n");
		for (Capstone.CsInsn instruction : instructionList) {
			instStr = instStr.concat(String.format("0x%x:\t%s\t %s\n", (int) instruction.address, instruction.mnemonic, instruction.opStr));
			//System.out.printf("0x%x:\t%s\t%s\n", (int) instruction.address, instruction.mnemonic, instruction.opStr);
		}
		//instStr = instStr.concat("-------END-------\n");
		instStr = instStr.concat("references: ");
		for (int reference:addressReferences) {
			instStr = instStr.concat(("0x"+Integer.toHexString(reference)+"; "));
		}
		for (int reference:loopAddressReferences) {
			instStr = instStr.concat(("0x"+Integer.toHexString(reference)+"; "));
		}
		instStr = instStr.concat("\n");
		return instStr;
	}

	public void addInstruction(Capstone.CsInsn instruction) {
		if(this.instructionList.isEmpty()) {
			this.startAddress = (int) instruction.address;
			this.endAddress = (int) instruction.address;
		} else {
			this.endAddress = (int) instruction.address;
		}
		this.instructionList.add(instruction);
	}

	public void addAddressReference(int reference) {
		this.addressReferences.add(reference);
	}

	public void addAddressReferenceOutOfScope(int reference) {
		this.outOfScopeReferences.add(reference);
	}
	
	public void addLoopAddressReference(int reference) {
		if (!this.addressReferences.contains(reference)) {
			this.loopAddressReferences.add(reference);
		}
	}

	public void addPtrReference(String reference) {
		this.ptrReferences.add(reference);
	}
	
	public HashSet<Integer> getAddressReferenceList() {
		return this.addressReferences;
	}
	
	public HashSet<Integer> getLoopAddressReferences() {
		return this.loopAddressReferences;
	}
	
	public boolean isEmpty() {
		return this.instructionList.isEmpty();
	}
	
	
	
	public int getParentCount() {
		return this.parents.size();
	}
	 
	public void setAsFunction() {
		this.isFunction = true;
	}
	
	public boolean isFunction() {
		return this.isFunction;
	}
	
	

	/**
	 * public int getStartAddress() { // TODO Auto-generated method stub return
	 * this.startAddress; }
	 * 
	 * public int getLastAddress() { // TODO Auto-generated method stub return
	 * this.endAddress; }
	 * 
	 * public Capstone.CsInsn getFirstInstruction() { // TODO Auto-generated method
	 * stub return instructionBlock.get(0); }
	 **/
}
