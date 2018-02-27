package program;

import java.util.ArrayList;

import capstone.Capstone;

public class BasicBlock {
	private int startAddress;
	private ArrayList<Capstone.CsInsn> instructionBlock;
	private int endAddress;
	
	public BasicBlock(Capstone.CsInsn first) {
		instructionBlock = new ArrayList<Capstone.CsInsn>();
		instructionBlock.add(first);
		this.startAddress = (int) first.address;
		this.endAddress = (int) first.address;
	}

	public int getBlockSize() {
		return 1;
	}

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
	}
}
