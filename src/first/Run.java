package first;

public class Run {

	public static void main(String[] args) {
		// Assemble all the pieces of the MVC
		Model m = new Model("Sylvain", "Saurel");
		View v = new View("Disassembler");
		Controller c = new Controller(m, v);
		c.initController();
	}

}