package program;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import capstone.Capstone;
import capstone.Capstone.CsInsn;

public class BasicBlock {
	private int startAddress;
	private ArrayList<Capstone.CsInsn> addressList;
	private int endAddress;
	private HashSet<Integer> addressReferences = new HashSet<Integer>();
	private HashSet<Integer> outOfScopeReferences = new HashSet<Integer>();
	private ArrayList<String> ptrReferences = new ArrayList<String>();

	public BasicBlock() {
		addressList = new ArrayList<Capstone.CsInsn>();
	}

	public int getBlockSize() {
		return this.addressList.size();
	}

	public int getFirst() {
		return (int) this.addressList.get(0).address;
	}

	public void printInstructions() {
		System.out.println("-------START-------");
		for (Capstone.CsInsn instruction : addressList) {
			System.out.printf("0x%x:\t%s\t%s\n", (int) instruction.address, instruction.mnemonic, instruction.opStr);
		}
		System.out.println("-------END-------");
		System.out.print("references: ");
		for (int reference:addressReferences) {
			System.out.print(reference+"; ");
		}
		System.out.println();

	}

	public void addInstruction(Capstone.CsInsn instruction) {
		this.addressList.add(instruction);
	}

	public void addAddressReference(int reference) {
		this.addressReferences.add(reference);
	}

	public void addAddressReferenceOutOfScope(int reference) {
		this.outOfScopeReferences.add(reference);
	}

	public void addPtrReference(String reference) {
		this.ptrReferences.add(reference);
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
