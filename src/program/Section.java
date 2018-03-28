package program;

public class Section {
	
	private String sectionName;
	private int address;
	
	public Section(String name, int address) {
		this.sectionName = name;
		this.address = address;
	}
	
	public String getName() {
		return this.sectionName;
	}
	
	public int getAddress() {
		return this.address;
	}
}
