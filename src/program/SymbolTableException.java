package program;

/**
 * thrown in Symbol Entry if there's an error
 * @author gurjan
 *
 */
public class SymbolTableException extends Exception {
	public SymbolTableException(String message) {
		super(message);
	}
}
