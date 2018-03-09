package tests;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import org.junit.Before;
import org.junit.jupiter.api.Test;

import capstone.Capstone;
import elf.Elf;
import elf.SectionHeader;
import program.BasicBlock;

class BasicBlockTests {
	
	private Elf elf; 
	private File f;
	private byte[] data;
	private int entry;
	private byte[] text_bytes;
	private byte[] instruction_bytes;
	Capstone cs;		
	
    private static SectionHeader getTextSection(Elf elf) {
    	for(SectionHeader shrs : elf.sectionHeaders) {
    		if(shrs.getName().equals(".text")) {
    			return shrs;
    		}
    	}
    	return elf.sectionHeaders[1];
    }
    
	private static Capstone.CsInsn disasmInstructionAtAddress(int address, byte[] data, Capstone cs) {
		byte[] instruction_bytes = Arrays.copyOfRange(data, (int) address, (int) address+15);
		Capstone.CsInsn[] allInsn = cs.disasm(instruction_bytes,address,1);
		return allInsn[0];
	}
    
	@Before public void setup() throws IOException {
		Path path = Paths.get("maze");
		this.f = new File("maze");
	    this.data = Files.readAllBytes(path); //convert the executable to bytes
		this.elf = new Elf(f);
		this.entry = (int) (elf.header.entryPoint-0x400000);
		long textSize = getTextSection(elf).size;
		text_bytes = Arrays.copyOfRange(data, entry, (int) (entry+textSize));
		this.cs = new Capstone(Capstone.CS_ARCH_X86, Capstone.CS_MODE_64);		
	}

	@Test //test 1, created getter for address hard coded to return 1
	void blockSizeTest() throws IOException {
		setup();
		BasicBlock block = new BasicBlock(disasmInstructionAtAddress(0x9b0,this.data,this.cs));
		assertEquals("TEST 1: instructions are added to block", block.getBlockSize(),1);
	}
	
	@Test //test 2, created getter for first addr hardcoded
	void firstAddressTest() throws IOException {
		setup();
		BasicBlock block = new BasicBlock(disasmInstructionAtAddress(0x9b0,this.data,this.cs));
		assertEquals("TEST 2: test first instruction in block is right", block.getStartAddress(),0x9b0);
	}
	
	@Test //test 3, added getter for last address
	void lastAddressTest() throws IOException {
		setup();
		BasicBlock block = new BasicBlock(disasmInstructionAtAddress(0x9b0,this.data,this.cs));
		assertEquals("TEST 3: test last instruction in block is right", block.getLastAddress(),0x9b0);
	}
	
	@Test //test 4, made so getter actually gets last address and LA is set in constructor
	void lastAddressTest2() throws IOException {
		setup();
		BasicBlock block = new BasicBlock(disasmInstructionAtAddress(0x9b2,this.data,this.cs));
		assertEquals("TEST 4: test last instruction in block is right", block.getLastAddress(),0x9b2);
	}
	
	@Test //test 5, made so getter actually gets first address and FA is set in constructor
	void firstAddressTest2() throws IOException {
		setup();
		BasicBlock block = new BasicBlock(disasmInstructionAtAddress(0x9b2,this.data,this.cs));
		assertEquals("TEST 5: test first instruction in block is right", block.getStartAddress(),0x9b2);
	}
	
	@Test //test 6 now instructions are actually added to the block
	void testFirstInstructionInBlock() throws IOException {
		setup();
		BasicBlock block = new BasicBlock(disasmInstructionAtAddress(0x9b0,this.data,this.cs));
		assertEquals("TEST 6: test first instruction in block is right", 
				block.getFirstInstruction().address,disasmInstructionAtAddress(0x9b0,this.data,this.cs).address);
	}
	
	@Test //test 6 now instructions are actually added to the block
	void testSecondInstructionInBlock() throws IOException {
		setup();
		BasicBlock block = new BasicBlock(disasmInstructionAtAddress(0x9b0,this.data,this.cs));
		assertEquals("TEST 6: test first instruction in block is right", 
				block.getFirstInstruction().address,disasmInstructionAtAddress(0x9b0,this.data,this.cs).address);
	}

}
