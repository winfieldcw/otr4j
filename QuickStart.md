# Quick Start Guide #

## otr4j main interfaces and their usage ##

otr4j exposes 3 main interfaces, OtrEngine, OtrKeyManager and OtrEngineHost. In this page we will discuss those interfaces and their usage.

### OtrEngine ###

Definition:

```
public interface OtrEngine {

	public String transformReceiving(SessionID sessionID, String content);
	public String transformSending(SessionID sessionID, String content);
	
	public void startSession(SessionID sessionID);
	public void endSession(SessionID sessionID);
	public void refreshSession(SessionID sessionID);
	
	public void addOtrEngineListener(OtrEngineListener l);
	public void removeOtrEngineListener(OtrEngineListener l);
	public SessionStatus getSessionStatus(SessionID sessionID);
	
	public PublicKey getRemotePublicKey(SessionID sessionID);
}
```

OtrEngine defines the Off-the-Record functionality and OtrEngineImpl is an implementation of OtrEngine. It is used to:

  1. Manage the encrypted session (startSession, endSession, refreshSession)
  1. Encrypt outgoing & decrypt incoming messages (transformSending, transformReceiving)
  1. Get the session status (getSessionStatus) and inform about session status changes (through the OtrEngineListener).

### OtrEngineHost ###

Definition:

```
public interface OtrEngineHost {
	public void injectMessage(SessionID sessionID, String msg);
	public void showWarning(SessionID sessionID, String warning);
	public void showError(SessionID sessionID, String error);
	public OtrPolicy getSessionPolicy(SessionID sessionID);
	public KeyPair getKeyPair(SessionID sessionID);
}
```

OtrEngineHost defines the functionality the host application must provide to OtrEngine. You have to pass an OtrEngineHost as an argument to the OtrEngineImpl constructor. OtrEngineHost is used by OtrEngine to:

  1. Inject messages, for example during the Authenticated Key Exchange.
  1. Notify the host application about warnings and errors.
  1. Get the session Off-the-Record policy.
  1. Get the session long-term KeyPair. **In this method implementation you will want to call OtrKeyManager.loadLocalKeyPair() and if that returns null, call OtrKeyManager.generateLocalKeyPair()**.

### OtrKeyManager ###

Definition:

```
public interface OtrKeyManager {

	public void addListener(OtrKeyManagerListener l);
	public void removeListener(OtrKeyManagerListener l);
	public void verify(SessionID sessionID);
	public void unverify(SessionID sessionID);
	public boolean isVerified(SessionID sessionID);
	
	public String getRemoteFingerprint(SessionID sessionID);
	public String getLocalFingerprint(SessionID sessionID);
	
	public void savePublicKey(SessionID sessionID, PublicKey pubKey);
	public void generateLocalKeyPair(SessionID sessionID);
	
	public PublicKey loadRemotePublicKey(SessionID sessionID);
	public KeyPair loadLocalKeyPair(SessionID sessionID);
}
```

OtrKeyManager defines the key management functionality and OtrKeyManagerImpl is an implementation of OtrKeyManager. It is completely decoupled from OtrEngine, so you can implement an alternative OtrKeyManager that stores/loads keys in a specific way. It is used to:

  1. Verify/Unverify sessions (through their respective methods).
  1. Get the session verification status (isVerified) and inform about verification status changes (through OtrKeyManagerListener)
  1. Get fingerprints for the host application to display (getRemoteFingerprint, getLocalFingerprint)
  1. Save public key of remote parties. **The host application has to call this method method when a session status changes to encrypted. (This can be improved, it shouldn't be the host application responsibility to save the public key)**.
  1. Load local key pairs or generate new KeyPairs (this is usually done in OtrEngineHost.getKeyPair(), as described above).
  1. Load remote public keys. **When a session goes encrypted the host application will want to check if the remote public key equals the one stored by the OtrKeyManager, and if yes to check if that key is verified or not**.

### Putting it all together (in a working example) ###

In this example we will create a DummyOtrEngineHost, inheriting from OtrEngineHost off course, and demonstrate session initiation (method startSession), encrypted message exchange (method exchangeMessages) and session termination (method endSession).

Pay attention to the fact that we mostly use 4 methods, startSession, transformReceiving, transformSending and endSession.

This class is part of the test cases included with the library and the procedure is instrumented in method testSession. It can be found under test/net/java/otr4j/OtrEngineImplTest.java.

```
package net.java.otr4j;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

import net.java.otr4j.OtrPolicy;
import net.java.otr4j.OtrEngineImpl;
import net.java.otr4j.OtrPolicyImpl;
import net.java.otr4j.session.SessionID;
import net.java.otr4j.session.SessionStatus;

public class OtrEngineImplTest extends junit.framework.TestCase {

	private SessionID aliceSessionID = new SessionID("Alice@Wonderland",
			"Bob@Wonderland", "Scytale");

	private SessionID bobSessionID = new SessionID("Bob@Wonderland",
			"Alice@Wonderland", "Scytale");

	private static Logger logger = Logger.getLogger(OtrEngineImplTest.class
			.getName());

	class DummyOtrEngineHost implements OtrEngineHost {
		public DummyOtrEngineHost(OtrPolicy policy) {
			this.policy = policy;
		}

		private OtrPolicy policy;
		public String lastInjectedMessage;

		public OtrPolicy getSessionPolicy(SessionID ctx) {
			return this.policy;
		}

		public void injectMessage(SessionID sessionID, String msg) {
			this.lastInjectedMessage = msg;
			String msgDisplay = (msg.length() > 10) ? msg.substring(0, 10)
					+ "..." : msg;
			logger.finest("IM injects message: " + msgDisplay);
		}

		public void showError(SessionID sessionID, String error) {
			logger.severe("IM shows error to user: " + error);
		}

		public void showWarning(SessionID sessionID, String warning) {
			logger.warning("IM shows warning to user: " + warning);
		}

		public void sessionStatusChanged(SessionID sessionID) {
			// don't care.
		}

		public KeyPair getKeyPair(SessionID paramSessionID) {
			KeyPairGenerator kg;
			try {
				kg = KeyPairGenerator.getInstance("DSA");

			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
				return null;
			}

			return kg.genKeyPair();
		}
	}

	public void testSession() throws Exception {
		this.startSession();
		this.exchageMessages();
		this.endSession();
	}

	private OtrEngineImpl usAlice;
	private OtrEngineImpl usBob;
	private DummyOtrEngineHost host;

	private void startSession() {
		host = new DummyOtrEngineHost(new OtrPolicyImpl(OtrPolicy.ALLOW_V2
				| OtrPolicy.ERROR_START_AKE));

		usAlice = new OtrEngineImpl(host);
		usBob = new OtrEngineImpl(host);

		usAlice.startSession(aliceSessionID);

		// Bob receives query, sends D-H commit.
		usBob.transformReceiving(bobSessionID, host.lastInjectedMessage);

		// Alice received D-H Commit, sends D-H key.
		usAlice
				.transformReceiving(aliceSessionID,
						host.lastInjectedMessage);

		// Bob receives D-H Key, sends reveal signature.
		usBob.transformReceiving(bobSessionID, host.lastInjectedMessage);

		// Alice receives Reveal Signature, sends signature and goes secure.
		usAlice
				.transformReceiving(aliceSessionID,
						host.lastInjectedMessage);

		// Bobs receives Signature, goes secure.
		usBob.transformReceiving(bobSessionID, host.lastInjectedMessage);

		if (usBob.getSessionStatus(bobSessionID) != SessionStatus.ENCRYPTED
				|| usAlice.getSessionStatus(aliceSessionID) != SessionStatus.ENCRYPTED)
			fail("Could not establish a secure session.");
	}

	private void exchageMessages() {
		// We are both secure, send encrypted message.
		String clearTextMessage = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what is that supposed to mean?";
		String sentMessage = usAlice.transformSending(aliceSessionID,
				clearTextMessage);

		// Receive encrypted message.
		String receivedMessage = usBob.transformReceiving(bobSessionID,
				sentMessage);

		if (!clearTextMessage.equals(receivedMessage))
			fail();

		// Send encrypted message.
		clearTextMessage = "Hey Alice, it means that our communication is encrypted and authenticated.";
		sentMessage = usBob.transformSending(bobSessionID, clearTextMessage);

		// Receive encrypted message.
		receivedMessage = usAlice.transformReceiving(aliceSessionID,
				sentMessage);

		if (!clearTextMessage.equals(receivedMessage))
			fail();

		// Send encrypted message.
		clearTextMessage = "Oh, is that all?";
		sentMessage = usAlice
				.transformSending(aliceSessionID, clearTextMessage);

		// Receive encrypted message.
		receivedMessage = usBob.transformReceiving(bobSessionID, sentMessage);
		if (!clearTextMessage.equals(receivedMessage))
			fail();

		// Send encrypted message.
		clearTextMessage = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.";
		sentMessage = usBob.transformSending(bobSessionID, clearTextMessage);

		// Receive encrypted message.
		receivedMessage = usAlice.transformReceiving(aliceSessionID,
				sentMessage);

		if (!clearTextMessage.equals(receivedMessage))
			fail();

		// Send encrypted message. Test UTF-8 space characters.
		clearTextMessage = "Oh really?! pouvons-nous parler en français?";

		sentMessage = usAlice
				.transformSending(aliceSessionID, clearTextMessage);

		// Receive encrypted message.
		receivedMessage = usBob.transformReceiving(bobSessionID, sentMessage);
		if (!clearTextMessage.equals(receivedMessage))
			fail();
	}

	private void endSession() {
		usBob.endSession(bobSessionID);
		usAlice.endSession(aliceSessionID);

		if (usBob.getSessionStatus(bobSessionID) != SessionStatus.PLAINTEXT
				|| usAlice.getSessionStatus(aliceSessionID) != SessionStatus.PLAINTEXT)
			fail("Failed to end session.");
	}
}

```