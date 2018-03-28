package program;

/**
 * If a file is not an ELF this exception is raised
 * @author gurjan
 *
 */
public class ElfException extends Exception{
	public ElfException(String message) {
		super(message);
	}
}
