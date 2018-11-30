import java.util.LinkedList;
import java.util.Queue;
import java.util.Random;

/**
 * This class serves as the universal user class
 * for both Alice and Trent. RSA public/private
 * key pair will be generated as indicated in
 * the project instructions.
 * 
 * @author Weiqiang Li
 *
 */
public class User {
	
	private String randomIntHolder; // print for random integer, line 124
	private String primeFailHolder; // print for failed prime test, line 139
	private String primePassHolder; // print for passed prime test, line 145
	private String publicKeyHolder; // print for finding e, line 162
	private String privateKeyHolder; // print for finding d, line 173
	private String keyPairHolder; // print for final key pair, line 177
	private String certificateHolder; // print for digital certificate generation, line 207 and line 209
	
	private int p; // prime p
	private int q; // prime q
	private int n; // p * q
	private int e; // public key
	private int d; // private key
	private int hc; // certificate h(r)
	private int sc; // certificate signature s
	
	private String name; // the name of this user
	private LinkedList<User> userInbox; // the inbox for user list
	private LinkedList<Integer> messageInbox; // the inbox for message list
	private boolean failTest; // indicator for fail test, fail test will only be run when this is true
	
	public User(String name) {
		this.name = name;
		this.userInbox = new LinkedList<User>();
		this.messageInbox = new LinkedList<Integer>();
		this.failTest = true;
	}
	
	/**
	 * Trent only: this method prints the key pair generated in detailed format.
	 */
	public void printKeyPair() {
		String trentHolder = keyPairHolder.replace("line:177", "line:185"); // for Trent the line# is changed
		System.out.print(trentHolder);
	}
	
	/**
	 * Alice only: this method prints the certificate string generated in detailed format.
	 */
	public void printCertificate() {
		System.out.print(certificateHolder);
	}
	
	/**
	 * Alice only: this method prints the strings illustrating the algorithm design clearly.
	 * Each kind of string trace will be printed only once.
	 */
	public void printAll() {
		System.out.println(randomIntHolder);
		System.out.println(primeFailHolder);
		System.out.println(primePassHolder);
		System.out.println(publicKeyHolder);
		System.out.println(privateKeyHolder);
		System.out.print(keyPairHolder);
	}
	
	/**
	 * This method generates a random integer.
	 * @param replace - whether the string to be printed needs to be replaced
	 * @return the generated random integer with 7 bits
	 */
	private int getRandomInt(boolean replace) {
		StringBuilder str = new StringBuilder();
		str.append("line:124\n");
		int x = 0; // this is the number to be returned
		x = x | (1 << 0); // set bit 0 to 1
		x = x | (1 << 6); // set bit 6 to 1
		Random random = new Random();
		for (int i = 5; i > 0; i--) {
			int k = random.nextInt(); // get random number
			str.append("b_" + i + "|");
			str.append(String.format("%32s", Integer.toBinaryString(k)).replace(' ', '0')); // padding with leading zeroes
			int b = k & 1; // the last bit
			str.append("|" + b + "\n");
			if (b != 0) {
				x = x | (1 << i); // if the bit is 1, set the i-th bit
			}
		}
		str.append("Number|" + x + "|" + String.format("%32s", Integer.toBinaryString(x)).replace(' ', '0') + "\n");
		if (replace) {
			randomIntHolder = str.toString();
		}
		return x;
	}
	
	/**
	 * User-defined modulo function, calculates x mod m.
	 * @param x
	 * @param m
	 * @return x mod m
	 */
	private int modulo(int x, int m) {
		while (x >= m) {
			x = x - m;
		}
		return x;
	}
	
	/**
	 * This method performs a single primality testing using Miller-Rabin method.
	 * @param m - the number to be tested
	 * @param a - a random chosen number, 0 < a < m
	 * @param replacePass - whether the string to be printed of a passed test needs to be replaced
	 * @param replaceFail - whether the string to be printed of a failed test needs to be replaced
	 * @return true if Miller-Rabin says m is perhaps a prime
	 */
	private boolean primalityTesting(int m, int a, boolean replacePass, boolean replaceFail) {
		StringBuilder str = new StringBuilder();
		str.append("line:139\n");
		int x = m - 1;
		int y = 1;
		int k = Integer.numberOfTrailingZeros(Integer.highestOneBit(x)); // get the location of most significant bit
		str.append("n = " + m + ", a = " + a + "\n");
		str.append(String.format("%-2s|%-3s|%-4s|%-4s|%-4s\n", "i", "xi", "z", "y", "y"));
		for (int i = k; i >= 0; i--) {
			int z = y;
			y = modulo(y * y, m);
			int xi = (x & (1 << i)) == 0 ? 0 : 1;
			int yi = y;
			if (y == 1 && z != 1 && z != m - 1) {
				str.append(String.format("%-2s|%-3s|%-4s|%-4s|%-4s\n", i, xi, z, yi, ""));
				while (--i >= 0) {
					xi = (x & (1 << i)) == 0 ? 0 : 1;
					str.append(String.format("%-2s|%-3s|%-4s|%-4s|%-4s\n", i, xi, "", "", ""));
				}
				str.append(m + " is not a prime because " + z + "^2 mod " + m + " == 1 and " + z + " != 1 and " + z + " != " + m + " - 1\n");
				if (replaceFail) {
					primeFailHolder = str.toString();
				}
				return false;
			}
			if (xi == 1) {
				y = modulo(y * a, m);
			}
			str.append(String.format("%-2s|%-3s|%-4s|%-4s|%-4s\n", i, xi, z, yi, y));
		}
		if (y != 1) {
			str.append(m + " is not a prime because " + a + "^" + x + " mod " + m + " != 1\n");
			if (replaceFail) {
				primeFailHolder = str.toString();
			}
			return false;
		}
		str.append(m + " is perhaps a prime\n");
		if (replacePass) {
			str.replace(5, 8, "145");
			primePassHolder = str.toString();
		}
		return true;
	}
	
	/**
	 * This method performs Miller-Rabin tests using 20 random a's where 0 < a < m.
	 * @param m - the number to b tested
	 * @param replacePass - whether the string to be printed of a passed test needs to be replaced
	 * @param replaceFail - whether the string to be printed of a failed test needs to be replaced
	 * @return true if 20 tests all passed
	 */
	private boolean millerRabin(int m, boolean replacePass, boolean replaceFail) {
		Random random = new Random();
		for (int i = 0; i < 20; i++) {
			int r = random.nextInt(65535);
			r = modulo(r, m);
			while (r == 0) {
				r = random.nextInt(65535);
				r = modulo(r, m);
			}
			if (!primalityTesting(m, r, replacePass, replaceFail)) {
				failTest = false;
				return false;
			}
		}
		return true;
	}
	
	/**
	 * This method generates a random number which is even, guaranteed not to be prime.
	 * @return the generated number
	 */
	private int randomIntNotPrime() {
		Random random = new Random();
		int k = random.nextInt(127);
		while (k <= 2 || modulo(k, 2) != 0) {
			k = random.nextInt(127);
		}
		return k;
	}
	
	/**
	 * This method simulates a failed Miller-Rabin test using a number which is not prime.
	 */
	private void millerRabinFailTest() {
		int m = randomIntNotPrime();
		while (millerRabin(m, false, true)) {
			m = randomIntNotPrime();
		}
	}
	
	/**
	 * This method performs a single public key test using Extended Euclidean Algorithm.
	 * @param k - the public key to be tested
	 * @param phi - the phi(n) relative to the prime
	 * @param str - string holder
	 * @return the last { si, ti, r } inside a integer array
	 */
	private int[] publicKeyTest(int k, int phi, StringBuilder str) {
		str.append("e = " + k + "\n");
		str.append(String.format("%-2s|%-7s|%-7s|%-7s|%-7s|%-6s|%-6s\n", "i", "qi", "r", "ri+1", "ri+2", "si", "ti"));
		int i = 1;
		Queue<Integer> rq = new LinkedList<Integer>(); // queue for r values
		Queue<Integer> qq = new LinkedList<Integer>(); // queue for q values
		Queue<Integer> sq = new LinkedList<Integer>(); // queue for s values
		Queue<Integer> tq = new LinkedList<Integer>(); // queue for t values
		rq.offer(phi); // add r1
		rq.offer(k); // add r2
		sq.offer(1); // add s1
		sq.offer(0); // add s2
		tq.offer(0); // add t1
		tq.offer(1); // add t2
		int r = rq.poll();
		int r1 = rq.peek();
		int si, ti;
		while (r1 != 0) {
			int r2 = modulo(r, r1);
			int qi = (r - r2) / r1;
			if (i > 2) {
				int q2 = qq.poll();
				int s2 = sq.poll();
				int t2 = tq.poll();
				si = s2 - q2 * sq.peek();
				ti = t2 - q2 * tq.peek();
				sq.offer(si);
				tq.offer(ti);
			} else {
				si = i == 1 ? 1 : 0;
				ti = i == 1 ? 0 : 1;
			}
			rq.offer(r2);
			qq.offer(qi);
			str.append(String.format("%-2s|%-7s|%-7s|%-7s|%-7s|%-6s|%-6s\n", i, qi, r, r1, r2, si, ti));
			r = r1;
			r1 = r2;
			i++;
		}
		if (i > 2) {
			int q2 = qq.poll();
			int s2 = sq.poll();
			int t2 = tq.poll();
			si = s2 - q2 * sq.peek();
			ti = t2 - q2 * tq.peek();
		} else {
			si = i == 1 ? 1 : 0;
			ti = i == 1 ? 0 : 1;
		}
		str.append(String.format("%-2s|%-7s|%-7s|%-7s|%-7s|%-6s|%-6s\n", i, "", r, "", "", si, ti));
		return new int[] { si, ti, r };
	}
	
	/**
	 * This method find RSA public/private keys starting with e = 3.
	 * @param phi - the phi(n) relative to the prime
	 * @return { e, d } public/private key pair, or null if cannot find one
	 */
	private int[] findKeys(int phi) {
		StringBuilder str = new StringBuilder();
		str.append("line:162\n");
		for (int k = 3; k <= phi; k++) {
			int[] temp = publicKeyTest(k, phi, str);
			if (temp[2] == 1) {
				int ti = temp[1];
				while (ti < 0) {
					ti = ti + phi;
				}
				publicKeyHolder = str.toString();
				privateKeyHolder = "line:173\nd = " + ti + "\n";
				return new int[] { k, ti };
			}
		}
		return null;
	}
	
	/**
	 * Assign value to p if passes Miller-Rabin.
	 */
	private void getP() {
		p = getRandomInt(true);
		while (!millerRabin(p, true, true)) {
			p = getRandomInt(true);
		}
	}
	
	/**
	 * Assign value to q if passes Miller-Rabin and not equal to p.
	 */
	private void getQ() {
		q = getRandomInt(false);
		while (!millerRabin(q, false, true) || q == p) {
			q = getRandomInt(false);
		}
	}
	
	/**
	 * Assign public/private key pairs. If cannot find one using the current p and q,
	 * this method will generate new p and q.
	 */
	private void getKeyPairs() {
		int phi = 0;
		int[] keys = findKeys(phi);
		while (keys == null) {
			getP();
			getQ();
			n = p * q;
			phi = (p - 1) * (q - 1);
			keys = findKeys(phi);
		}
		e = keys[0];
		d = keys[1];
	}
	
	/**
	 * Format the final key pair into a string.
	 */
	private void formatKeyPair() {
		StringBuilder str = new StringBuilder();
		str.append("line:177\n");
		str.append("p = " + p + ", q = " + q + ", n = " + n + ", e = " + e + ", d = " + d + "\n");
		str.append("p = " + String.format("%32s", Integer.toBinaryString(p)).replace(' ', '0') + "\n");
		str.append("q = " + String.format("%32s", Integer.toBinaryString(q)).replace(' ', '0') + "\n");
		str.append("n = " + String.format("%32s", Integer.toBinaryString(n)).replace(' ', '0') + "\n");
		str.append("e = " + String.format("%32s", Integer.toBinaryString(e)).replace(' ', '0') + "\n");
		str.append("d = " + String.format("%32s", Integer.toBinaryString(d)).replace(' ', '0') + "\n");
		keyPairHolder = str.toString();
	}
	
	/**
	 * Run all the associated algorithms and generate key pair.
	 */
	public void generate() {
		getKeyPairs();
		if (failTest) {
			millerRabinFailTest(); // only run fail test when necessary
		}
		formatKeyPair();
	}
	
	/**
	 * Return public key e of this user.
	 * @return public key e
	 */
	public int getPublicKey() {
		return this.e;
	}
	
	/**
	 * Return the number n of this user.
	 * @return number n
	 */
	public int getPublicN() {
		return this.n;
	}
	
	/**
	 * Return the name of this user.
	 * @return name
	 */
	public String getName() {
		return this.name;
	}
	
	/**
	 * Assign the formatted certificate string to be printed.
	 * @param certificateHolder - the certificate string
	 */
	public void setCertificateString(String certificateHolder) {
		this.certificateHolder = certificateHolder;
	}
	
	/**
	 * Assign the digital certificate.
	 * @param hc - certificate h(r)
	 * @param sc - certificate signature s
	 */
	public void setCertificate(int hc, int sc) {
		this.sc = sc;
		this.hc = hc;
	}
	
	/**
	 * Return the certificate h(r).
	 * @return h(r)
	 */
	public int getCertificate() {
		return this.hc;
	}
	
	/**
	 * Return the certificate signature s.
	 * @return s
	 */
	public int getCertificateSignature() {
		return this.sc;
	}
	
	/**
	 * Hash function to compute h(r).
	 * @param r - the string to be hashed
	 * @return h(r)
	 */
	public int computeHash(String r) {
		int h = 0;
		for (int i = 0; i < r.length(); i += 8) {
			int temp = Integer.parseInt(r.substring(i, i + 8), 2);
			h = h ^ temp;
		}
		return h;
	}
	
	/**
	 * Computes fast exponentiation of a^x modulo m.
	 * @param m
	 * @param a
	 * @param x
	 * @param verbose - if set to true, print the detailed calculation process in table format
	 * @return a^x modulo m
	 */
	public int fastExponentiation(int m, int a, int x, boolean verbose) {
		StringBuilder str = new StringBuilder();
		str.append("line:242\n");
		int y = 1;
		int k = Integer.numberOfTrailingZeros(Integer.highestOneBit(x)); // get the location of most significant bit
		str.append(String.format("%-2s|%-3s|%-6s|%-6s\n", "i", "xi", "y", "y"));
		for (int i = k; i >= 0; i--) {
			y = modulo(y * y, m);
			int xi = (x & (1 << i)) == 0 ? 0 : 1;
			int yi = y;
			if (xi == 1) {
				y = modulo(y * a, m);
			}
			str.append(String.format("%-2s|%-3s|%-6s|%-6s\n", i, xi, yi, y));
		}
		if (verbose) {
			System.out.print(str);
		}
		return y;
	}
	
	/**
	 * Decrypt a cipher using the user's own private key.
	 * @param cipher - the cipher to be decrypted
	 * @return the original message
	 */
	public int decrypt(int cipher) {
		return fastExponentiation(n, cipher, d, false);
	}
	
	/**
	 * Encrypt a message using a certain user's public key.
	 * @param message - the message to be encrypted
	 * @param user - the public key pair of the user to be used
	 * @return the cipher
	 */
	public int encrypt(int message, User user) {
		return fastExponentiation(user.getPublicN(), message, user.getPublicKey(), false);
	}
	
	/**
	 * Send a message to a specific user.
	 * @param message - the message to be sent
	 * @param user - the user to receive the message
	 */
	public void sendMessage(int message, User user) {
		user.userInbox.push(this);
		user.messageInbox.push(message);
	}
	
	/**
	 * Extract the newest received message - must be used together with receiveUser().
	 * @return the newest received message 
	 */
	public int receiveMessage() {
		if (this.messageInbox.size() > 0) {
			return this.messageInbox.pop();
		}
		return -1; // empty inbox
	}
	
	/**
	 * Extract the newest received user - must be used together with receiveMessage().
	 * @return the newest received user 
	 */
	public User receiveUser() {
		if (this.userInbox.size() > 0) {
			return this.userInbox.pop();
		}
		return null; // empty inbox
	}
	
	/**
	 * Trent only: issue digital certificate for the user.
	 * @param user - the user to be issued the digital certificate
	 */
	public void issueDigitalCertificate(User user) {
		StringBuilder str = new StringBuilder();
		str.append("line:207\n");
		char[] formattedName = String.format("%6s", user.getName()).toCharArray();
		str.append("r = ");
		StringBuilder temp = new StringBuilder();
		for (int i = 0; i < 6; i++) {
			temp.append(String.format("%32s", Integer.toBinaryString(formattedName[i])).replace(' ', '0').substring(24));
		}
		temp.append(String.format("%32s", Integer.toBinaryString(user.getPublicN())).replace(' ', '0'));
		temp.append(String.format("%32s", Integer.toBinaryString(user.getPublicKey())).replace(' ', '0'));
		str.append(temp);
		str.append("\n");
		String r = temp.toString();
		int hr = computeHash(r);
		str.append("h(r) = " + String.format("%32s", Integer.toBinaryString(hr)).replace(' ', '0') + "\n");
		int sr = decrypt(hr);
		str.append("s = " + String.format("%32s", Integer.toBinaryString(sr)).replace(' ', '0') + "\n");
		str.append("\nline:209\nh(r) = " + hr + ", s = " + sr + "\n");
		user.setCertificateString(str.toString()); // certificate formatted string stored in the user's instance
		user.setCertificate(hr, sr); // certificated stored in the user's instance
	}

}
