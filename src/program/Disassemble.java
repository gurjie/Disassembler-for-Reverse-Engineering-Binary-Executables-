package program;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import capstone.Capstone;
import elf.Elf;
import elf.SectionHeader;



public class Disassemble {
	
	private boolean symtabExists;
	private Elf elf;
	private byte[] data;
    private byte[] text_bytes;
    private byte[] currentBytes;
    private int textSize;
	private ArrayList<Function> functions = new ArrayList<Function>();
	
	public Disassemble(File f) throws ReadException, ElfException {
		try {
			data = Files.readAllBytes(f.toPath());
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
		text_bytes = Arrays.copyOfRange(data, entry, (int) (entry+textSize));
	    textSize = (int) getTextSection(elf).size;
	    
		Capstone cs = new Capstone(Capstone.CS_ARCH_X86, Capstone.CS_MODE_64);
	    singleInstLinearSweep(entry, textSize, data, cs);
	    //discoverFunctions(entry, textSize, data, cs);
	}
	
	public List<Section> getSections() {
		List<Section> sections = new ArrayList<Section>();
    	for(SectionHeader shrs : this.elf.sectionHeaders) {
    		checkForSymtab(shrs);
    		Section current = new Section(shrs.getName());
    		sections.add(current);
    	}
    	return sections;
	}
	
	private void checkForSymtab(SectionHeader sectionHeader) {
		if (sectionHeader.getName().equals(".symtab")) {
			this.symtabExists = true;
		}
	}
	
	public boolean symTabExists() {
		return this.symtabExists;
	}
	
	/*private void discoverFunctions(int entry, int textSize, byte[] data, Capstone cs) {
		int address = entry;
		while (address<entry+textSize) {
			Capstone.CsInsn instruction = disasmInstructionAtAddress(address,data,cs,entry,textSize,1);
			if (instruction!=null) {
				if (instruction.mnemonic.equals("push")) {
					//System.out.println(instruction.insnName());
					Capstone.CsInsn secondInstruction = disasm2AtAddress(address,data,cs,entry,textSize);
					if (secondInstruction.mnemonic.equals("mov")) {
					    if(instruction.opStr.equals("rbp")) {
					    	if (secondInstruction.opStr.equals("rbp, rsp")) {
							    Function function = new Function();
						
							    }
					    	}
					    }

					}
				}
			}

			address+=1;	
		
		
	}*/
	
	/**
	 * 
	 * @param address address in the byte data representing the file to disassemble at
	 * @param data - bytes representing the executable
	 * @param cs capstone instance
	 * @param entry entry point of the elf
	 * @param textSize size of the text section in the elf
	 * @param count number of instructions to be disassmbled
	 */
	private static Capstone.CsInsn disasmInstructionAtAddress(int address, byte[] data, Capstone cs, int entry, long textSize, int count) {
		byte[] instruction_bytes = Arrays.copyOfRange(data, (int) address, (int) address+15);
		Capstone.CsInsn[] allInsn = cs.disasm(instruction_bytes,0x0+address,count);
		if(allInsn.length>0) {
			//System.out.printf("0x%x:\t%s\t%s\n", allInsn[0].address, allInsn[0].mnemonic, allInsn[0].opStr);
			return allInsn[0];
		}
		return null;
	}
	
	private static Capstone.CsInsn disasm2AtAddress(int address, byte[] data, Capstone cs, int entry, long textSize) {
		byte[] instruction_bytes = Arrays.copyOfRange(data, (int) address, (int) address+15);
		Capstone.CsInsn[] allInsn = cs.disasm(instruction_bytes,0x0+address,2);
		if(allInsn.length>0) {
			//System.out.printf("0x%x:\t%s\t%s\n", allInsn[0].address, allInsn[0].mnemonic, allInsn[0].opStr);
			return allInsn[1];
		}
		return null;
	}
	
	private void singleInstLinearSweep(int entry, int textSize, byte[] data, Capstone cs) {
		int InstSize = 0;
		while(entry+InstSize<entry+textSize) {
			text_bytes = Arrays.copyOfRange(data, entry+InstSize, (int) (entry+textSize));
			Capstone.CsInsn[] allInsn = cs.disasm(text_bytes, entry+InstSize,1);
			InstSize += allInsn[0].size;
		    System.out.printf("0x%x:\t%s\t%s\n", allInsn[0].address, allInsn[0].mnemonic, allInsn[0].opStr);
		}
	}
	
    private SectionHeader getTextSection(Elf elf) {
    	for(SectionHeader shrs : elf.sectionHeaders) {
    		if(shrs.getName().equals(".text")) {
    			return shrs;
    		}
    	}
    	return elf.sectionHeaders[1];
    }
	
	
	
}
