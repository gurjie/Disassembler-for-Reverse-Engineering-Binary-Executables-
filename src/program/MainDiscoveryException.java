package program;

/**
 * Thrown if there is an issue discovering main
 * @author gurjan
 *
 */
public class MainDiscoveryException extends Exception {
	public MainDiscoveryException(String message) {
		super(message);
	}
}
