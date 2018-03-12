package program;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import capstone.Capstone;
import capstone.Capstone.CsInsn;

public class BasicBlock {
	private int startAddress;
	private ArrayList<Capstone.CsInsn> instructionList;
	private int endAddress;
	private HashSet<Integer> addressReferences = new HashSet<Integer>();
	private HashSet<Integer> loopAddressReferences = new HashSet<Integer>();
	private HashSet<Integer> outOfScopeReferences = new HashSet<Integer>();
	private ArrayList<String> ptrReferences = new ArrayList<String>();

	public BasicBlock() {
		instructionList = new ArrayList<Capstone.CsInsn>();
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
	

	public String instructionsToString() {
		String instStr = "";
		instStr = instStr.concat("-------START-------\n");
		for (Capstone.CsInsn instruction : instructionList) {
			instStr = instStr.concat(String.format("0x%x:\t%s\t %s\n", (int) instruction.address, instruction.mnemonic, instruction.opStr));
			//System.out.printf("0x%x:\t%s\t%s\n", (int) instruction.address, instruction.mnemonic, instruction.opStr);
		}
		instStr = instStr.concat("-------END-------\n");
		instStr = instStr.concat("references: ");
		for (int reference:addressReferences) {
			instStr = instStr.concat((reference+"; "));
		}
		for (int reference:loopAddressReferences) {
			instStr = instStr.concat((reference+"; "));
		}
		instStr = instStr.concat("\n");
		return instStr;
	}

	public void addInstruction(Capstone.CsInsn instruction) {
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
