package tests;

public class addressCheckTests {
	public static void main(String[] args) {
		String opstr = "0x00890";
		
		try {
			long t = Long.decode(opstr.trim());
			System.out.println(t);
		} catch(NumberFormatException e) {
			System.out.println("errror");
			
		}
	}
}
