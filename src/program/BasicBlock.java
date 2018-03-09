package program;

import java.util.ArrayList;
import java.util.List;

import capstone.Capstone;

public class BasicBlock {
	private int startAddress;
	private ArrayList<Capstone.CsInsn> addressList;
	private int endAddress;
	private ArrayList<Integer> addressReferences = new ArrayList<Integer>();
	
	public BasicBlock() {
		addressList = new ArrayList<Capstone.CsInsn>();
	}

	public int getBlockSize() {
		return this.addressList.size();
	}
	
	public void addInstruction(Capstone.CsInsn instruction) {
		this.addressList.add(instruction);
	}

	public void addAddressReference(int reference) {
		this.addressReferences.add(reference);
	}
	/**
	public int getStartAddress() {
		// TODO Auto-generated method stub
		return this.startAddress;
	}

	public int getLastAddress() {
		// TODO Auto-generated method stub
		return this.endAddress;
	}

	public Capstone.CsInsn getFirstInstruction() {
		// TODO Auto-generated method stub
		return instructionBlock.get(0);
	}**/
}
