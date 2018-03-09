package program;

import java.util.ArrayList;
import java.util.List;

import capstone.Capstone;
import capstone.Capstone.CsInsn;

public class BasicBlock {
	private int startAddress;
	private ArrayList<Capstone.CsInsn> addressList;
	private int endAddress;
	private ArrayList<Integer> addressReferences = new ArrayList<Integer>();
	private ArrayList<String> ptrReferences = new ArrayList<String>();

	public BasicBlock() {
		System.out.println("new block!");
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

	}

	public void addInstruction(Capstone.CsInsn instruction) {
		this.addressList.add(instruction);
	}

	public void addAddressReference(int reference) {
		this.addressReferences.add(reference);
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
