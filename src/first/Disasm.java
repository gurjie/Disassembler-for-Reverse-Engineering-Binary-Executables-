package first;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import elf.Elf;



public class Disasm {
	
	private Elf elf;
	byte[] data;

	
	public Disasm(File f) throws ReadException, ElfException {
		File file = new File("maze");
		try {
			data = Files.readAllBytes(file.toPath());
		} catch (IOException e) {
			throw new ReadException("Error reading selected file into byte array.");
		}
		try {
			elf = new Elf(f);
		} catch (IOException e) {
			throw new ElfException(e.getMessage()+
					"\nPerhaps select an ELF 64 bit file");
		}
		int entry = (int) (elf.header.entryPoint - 0x400000);
	}
}
