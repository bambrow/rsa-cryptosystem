import java.util.Random;

/**
 * This class serves as the class simulating the
 * authentication process.
 * 
 * @author Weiqiang Li
 *
 */
public class Authentication {
	
	private String randomChallengeHolder; // print for k and u, line 231 and 233
	private String connectHolder; // print for authentication, line 239
	
	private User challenger; // challenger, hence Bob
	private User challengee; // chellengee, hence Alice
	
	private int u; // the challenge number picked
	private int m; // the transmitted message during authentication
	
	public Authentication(User challenger, User challengee) {
		this.challenger = challenger;
		this.challengee = challengee;
	}
	
	/**
	 * This method prints the strings illustrating the authentication process clearly.
	 */
	public void printAll() {
		System.out.println(randomChallengeHolder);
		System.out.println(connectHolder);
		challenger.fastExponentiation(challengee.getPublicN(), m, challengee.getPublicKey(), true); // for print of line 242
	}
	
	/**
	 * Generate the random agreement number between challenger and challengee.
	 * @return u, the random agreement number
	 */
	private int getU() {
		StringBuilder str = new StringBuilder();
		str.append("line:231\n");
		int n = challengee.getPublicN();
		int k = Integer.numberOfTrailingZeros(Integer.highestOneBit(n));
		int y = 0; // this is the number to be returned
		y = y | (1 << 0); // set bit 0 to 1
		y = y | (1 << (k-1)); // set bit k-1 to 1
		Random random = new Random();
		for (int i = k - 2; i > 0; i--) {
			int r = random.nextInt(); // get random number
			int b = r & 1; // the last bit
			if (b != 0) {
				y = y | (1 << i); // if the bit is 1, set the i-th bit
			}
		}
		str.append("k = " + k + ", u = " + y + "\n");
		str.append("\n");
		str.append("line:233\n");
		str.append("u = " + String.format("%32s", Integer.toBinaryString(y)).replace(' ', '0') + "\n");
		randomChallengeHolder = str.toString();
		return y;
	}
	
	/**
	 * Simulate the authentication between challenger and challengee, and 
	 * validate the identity.
	 */
	public void connect() {
		StringBuilder str = new StringBuilder();
		str.append("line:239\n");
		u = getU();
		int h = challengee.computeHash(String.format("%32s", Integer.toBinaryString(u)).replace(' ', '0'));
		int v = challengee.decrypt(h);
		challengee.sendMessage(v, challenger); // simulate the sender/receiver
		int message = challenger.receiveMessage();
		User user = challenger.receiveUser();
		int ev = challenger.encrypt(message, user); // this user is equal to challengee because chalengee sent the message
		str.append("u = " + u + ", h(u) = " + h + ", v = " + v + ", ev = " + ev + "\n");
		connectHolder = str.toString();
		m = message;
		assert(ev == h); // this must be true, Ev must be equal to h(u)
	}
	
}
