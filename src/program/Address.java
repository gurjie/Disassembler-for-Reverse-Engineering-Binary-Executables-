package program;

public class Address {
	int address;
	Instruction instruction;
	boolean visited;
	
	public Address(int address) {
		this.address = address;
	}
	
	public void setVisited() {
		this.visited = true;
	}
	
	public boolean hasBeenVisited() {
		return this.visited;
	}
	
}
