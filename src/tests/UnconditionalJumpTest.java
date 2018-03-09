package tests;

public class UnconditionalJumpTest {
	public static void main(String[] args) {
		String mnemonic = "jmp";
		
		if(mnemonic.matches("jmp|call|ret")) {
			System.out.println(true);
		}
	}
}
