package first;

import java.io.File;
import java.io.IOException;

public class Model {

	private File file;
	private int mode; 

	// Instantiated upon file -> load or loading a file
	public Model() {

	}
	
	public void setFile(File f) {
		this.file = f;
	}
	
	public void disassemble() throws ReadException, ElfException {
			Disasm instance = new Disasm(this.file);
	}
	
}
