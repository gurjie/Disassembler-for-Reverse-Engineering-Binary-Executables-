package program;

/**
 * Exceptione raised if there's an issue reading an executable into a sequence of bytes
 * @author gurjan
 *
 */
public class ReadException extends Exception{
	public ReadException(String message) {
		super(message);
	}
}
