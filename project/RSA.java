
/**
 * This class serves as the class running the
 * whole design.
 * 
 * @author Weiqiang Li
 *
 */
public class RSA {
	
	/**
	 * Get everything started!
	 */
	public static void run() {
		
		User alice = new User("Alice");
		alice.generate();
		alice.printAll();
		
		System.out.println();
		
		User trent = new User("Trent");
		trent.generate();
		trent.printKeyPair();
		
		System.out.println();
		
		trent.issueDigitalCertificate(alice);
		alice.printCertificate();
		
		System.out.println();
		
		User bob = new User("Bob");
		Authentication auth = new Authentication(bob, alice);
		auth.connect();
		auth.printAll();
		
	}
	
	public static void main(String[] args) {
		RSA.run();
	}
	
}


