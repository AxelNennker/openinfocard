package org.xmldap.sts.db.impl;

import java.io.ByteArrayInputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Properties;
import java.util.Vector;
import java.util.logging.Logger;

import org.xmldap.exceptions.StorageException;
import org.xmldap.sts.db.CardStorage;
import org.xmldap.sts.db.DbSupportedClaim;
import org.xmldap.sts.db.ManagedCard;
import org.xmldap.sts.db.SupportedClaims;

public class CardStorageEmbeddedDBImpl implements CardStorage {

	Logger log = Logger
			.getLogger("org.xmldap.sts.db.impl.CardStorageEmbeddedDBImpl");

	public final String USERNAME_LEN = "255";
	public final String PASSWORD_LEN = "255";

	public String framework = "embedded";
	public String driver = "org.apache.derby.jdbc.EmbeddedDriver";
	public String protocol = "jdbc:derby:";

	private Connection conn = null;

	private boolean initialized = false;

	static final int defaultVersion = 3; // since 201104
	int version = 0;

	SupportedClaims supportedClaimsImpl = null;

	public CardStorageEmbeddedDBImpl(SupportedClaims supportedClaimsImpl) {
		this.supportedClaimsImpl = supportedClaimsImpl;
	}

	private String claimsDefinition() {
		List<DbSupportedClaim> dbSupportedClaims = supportedClaimsImpl
				.dbSupportedClaims();
		if (dbSupportedClaims.size() > 0) {
			StringBuffer claimsDefinition = new StringBuffer();
			claimsDefinition.append(",");
			for (int i = 0; i < dbSupportedClaims.size() - 1; i++) {
				claimsDefinition.append(" ");
				DbSupportedClaim claim = dbSupportedClaims.get(i);
				claimsDefinition.append(claim.columnName);
				claimsDefinition.append(" ");
				claimsDefinition.append(claim.columnType);
				claimsDefinition.append(",");
			}
			claimsDefinition.append(" ");
			claimsDefinition.append(dbSupportedClaims.get(dbSupportedClaims
					.size() - 1).columnName);
			claimsDefinition.append(" ");
			claimsDefinition.append(dbSupportedClaims.get(dbSupportedClaims
					.size() - 1).columnType);
			return claimsDefinition.toString();
		} else {
			System.out.println("STS supported claims list is empty!!!");
			return "";
		}
	}

	private void createTableCards(Statement s) throws SQLException {
		String claimsDefinition = claimsDefinition();
		// " givenName varChar(50)," +
		// " surname varChar(50)," +
		// " emailAddress varChar(150)," +
		// " streetAddress varChar(50)," +
		// " locality varChar(50)," +
		// " stateOrProvince varChar(50)," +
		// " postalCode varChar(10)," +
		// " country varChar(50)," +
		// " primaryPhone varChar(50)," +
		// " dateOfBirth varChar(50)," +
		// " gender  varChar(10))";

		String query = "create table cards("
				+ "cardid varchar(255) NOT NULL CONSTRAINT CARD_PK PRIMARY KEY,"
				+ " cardName varchar(48) NOT NULL," + " cardVersion int,"
				+ " timeIssued varChar(50) NOT NULL," + " timeExpires varChar(50),"
				+ " requireStrongRecipientIdentity int,"
				+ " requireAppliesTo int,"
				+ " cardfrontimage varChar(32672),"
				+ " fronthtml varChar(32672),"
				+ " cardbackimage varChar(32672),"
				+ " backhtml varChar(32672)"
				+ claimsDefinition + ")";
		System.out.println(query);
		try {
			s.execute(query);
		} catch (SQLException e) {
			System.err.println("createTableCards threw Exception: " + e.getMessage());
			throw e;
		}
		System.out.println("Created table cards");
	}

	public void startup() {

		try {

			Class.forName(driver).newInstance();
			// System.out.println("Loaded the appropriate driver.");

			Properties props = new Properties();
			conn = DriverManager.getConnection(protocol
					+ supportedClaimsImpl.getClass().getName()
					+ "cardDB;create=true", props);

			System.out.println("Connected to "
					+ supportedClaimsImpl.getClass().getName() + "cardDB");

			conn.setAutoCommit(false);
			Statement s = conn.createStatement();
			ResultSet rs = null;

			try {
				rs = s.executeQuery("SELECT init,version FROM initialized");
				if (rs.next()) {
					// int init = rs.getInt(1);
					version = rs.getInt(2);
					System.out.println(supportedClaimsImpl.getClass().getName()
							+ "cardDB is already initialized. Version="
							+ version);
					if (version < defaultVersion) {
						throw new SQLException("need to recreate tables. All data will be lost!");
					}
					initialized = true;
				} else {
					System.err.println("ERROR: 'SELECT init,version FROM initialized' failed!!!");
				}

			} catch (SQLException e) {

				System.out.println("Not initialized - creating card tables");

				s
						.execute("create table accounts(username varchar("
								+ USERNAME_LEN
								+ ") NOT NULL CONSTRAINT ACCOUNT_PK PRIMARY KEY, password varchar("
								+ PASSWORD_LEN + "))");
				System.out.println("Created table accounts");

				createTableCards(s);

				s.execute("create table account_cards(username varchar("
						+ USERNAME_LEN + "), cardid varchar(255))");
				// TODO - figure out the foreign key constraints
				// s.execute(
				// "alter table account_cards ADD CONSTRAINT USERNAME_FK FOREIGN KEY (username) REFERENCES accounts (username)"
				// );
				// s.execute(
				// "alter table account_cards ADD CONSTRAINT CARD_FK FOREIGN KEY (cardid) REFERENCES cards (cardid)"
				// );
				System.out.println("Created table account_cards");

				s.execute("create table initialized(init int, version int)");
				s.execute("insert into initialized values (1, "
						+ defaultVersion + ")");
				version = defaultVersion;
				System.out.println(supportedClaimsImpl.getClass().getName()
						+ "cardDB initialized");

			} finally {
				s.close();
				conn.commit();
				// System.out.println("Closed result set and statement");
			}

		} catch (InstantiationException e) {
			e.printStackTrace();
		} catch (IllegalAccessException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (SQLException e) {
			e.printStackTrace();
		}

	}

	public void addAccount(String username, String password)
			throws StorageException {
		log.log(java.util.logging.Level.INFO, "addAccount: username ("
				+ username + ") password (" + password + ")");
		System.out.println("addAccount: username (" + username + ") password ("
				+ password + ")");
		if (username == null) {
			throw new StorageException("username can not be null");
		}
		if (password == null) {
			throw new StorageException("password can not be null");
		}
		if ("".equals(username)) {
			throw new StorageException("username can not be of zero length");
		}
		if ("".equals(password)) {
			throw new StorageException("password can not be of zero length");
		}
		if (username.length() > Integer.valueOf(USERNAME_LEN)) {
			throw new StorageException("username is longer than "
					+ Integer.valueOf(USERNAME_LEN));
		}
		if (password.length() > Integer.valueOf(PASSWORD_LEN)) {
			throw new StorageException("password is longer than "
					+ Integer.valueOf(PASSWORD_LEN));
		}
		if (conn == null) {
			startup();
		}

		PreparedStatement pstmt = null;
		try {
			pstmt = conn.prepareStatement("insert into accounts values (?,?)");
			pstmt.setString(1, username);
			pstmt.setString(2, password);
			try {

				pstmt.executeUpdate();
				pstmt.close();
				conn.commit();
			} catch (SQLException e) {

				// eat the exception for now
				// TODO - add an exception pattern
				System.err.println("Account creation failed: username=" + username + "\n" + e.getMessage());
				throw new StorageException("Account creation failed", e);

			} finally {

				pstmt.close();
				conn.commit();

			}

		} catch (SQLException e) {
			e.printStackTrace(); // To change body of catch statement use File |
									// Settings | File Templates.
		} 
	}

	public boolean authenticate(String uid, String password) {
		log.log(java.util.logging.Level.INFO, "authenticate: username (" + uid
				+ ") password (" + password + ")");
		System.out.println("authenticate: username (" + uid + ") password ("
				+ password + ")");
		if (uid == null) {
			return false;
		}
		if (password == null) {
			return false;
		}
		if ("".equals(uid)) {
			return false;
		}
		if ("".equals(password)) {
			return false;
		}
		if (uid.length() > Integer.valueOf(USERNAME_LEN)) {
			return false;
		}
		if (password.length() > Integer.valueOf(PASSWORD_LEN)) {
			return false;
		}
		if (conn == null) {
			startup();
		}

		boolean authenticated = false;

		PreparedStatement pstmt = null;
		try {
			pstmt = conn.prepareStatement("SELECT password FROM accounts where username = ?");
			pstmt.setString(1, uid);
			
			try {

				ResultSet rs = pstmt.executeQuery();
				if (!rs.next())
					return false;
				String pw = rs.getString(1);
				if (pw.equals(password))
					authenticated = true;
				pstmt.close();
				conn.commit();
			} catch (SQLException e) {

				// eat the exception for now
				// TODO - add an exception pattern
				e.printStackTrace();

			} finally {

				pstmt.close();
				conn.commit();

			}

		} catch (SQLException e) {
			e.printStackTrace(); // To change body of catch statement use File |
									// Settings | File Templates.
		}

		return authenticated;
	}

	public void addCard(String username, ManagedCard card) throws StorageException {
		if (conn == null) {
			startup();
		}

		PreparedStatement pstmt = null;
		try {
			List<DbSupportedClaim> dbSupportedClaims = supportedClaimsImpl
					.dbSupportedClaims();

			String statement = "insert into cards values (?,?,?,?,?";
			if (version > 1) {
				statement += ",?,?";
			}
			if (version > 2) {
				statement += ",?,?,?,?";
			}
			for (int i = 0; i < dbSupportedClaims.size(); i++) {
				statement += ",?";
			}
			statement += ")";
			pstmt = conn.prepareStatement(statement);

			try {

				// cardid, cardName , cardVersion, timeIssued , timeExpires,
				// givenName, surname, emailAddress, streetAddress, locality,
				// stateOrProvince, postalCode, country, primaryPhone,
				// dateOfBirth, privatePersonalIdentifier, gender

				// System.out.println("insert into cards values ('" +
				// card.getPrivatePersonalIdentifier() + "', '" +
				// card.getCardName() + "', " + card.getCardVersion() + ", '" +
				// card.getTimeIssued() + "', '" + card.getTimeExpires() +
				// "', '" + card.getGivenName() + "', '" + card.getSurname() +
				// "', '" + card.getEmailAddress() + "', '" +
				// card.getStreetAddress() + "', '" + card.getLocality() +
				// "', '" + card.getStateOrProvince() + "', '" +
				// card.getPostalCode() + "', '" + card.getCountry() + "', '" +
				// card.getPrimaryPhone() + "', '" + card.getDateOfBirth() +
				// "', '" + card.getGender() + "')");
				int parameterIndex = 1;
				pstmt.setString(parameterIndex++, card
						.getPrivatePersonalIdentifier());
				pstmt.setString(parameterIndex++, card.getCardName());
				pstmt.setInt(parameterIndex++, card.getCardVersion());
				pstmt.setString(parameterIndex++, card.getTimeIssued());
				String timeExpires = card.getTimeExpires();
				if (timeExpires != null) {
					pstmt.setString(parameterIndex++, timeExpires);
				} else {
					pstmt.setNull(parameterIndex++, java.sql.Types.VARCHAR);
				}
				if (version > 1) {
					// " requireStrongRecipientIdentity int" +
					// " requireAppliesTo int" +
					pstmt.setInt(parameterIndex++, (card
							.getRequireStrongRecipientIdentity()) ? 1 : 0);
					pstmt.setInt(parameterIndex++, (card
							.getRequireAppliesTo()) ? 1 : 0);
				}
				if (version > 2) {
					String cardfrontimage = card.getCardfrontimage();
					if (cardfrontimage != null) {
						pstmt.setString(parameterIndex++, cardfrontimage);
					} else {
						pstmt.setNull(parameterIndex++, java.sql.Types.VARCHAR);
					}
					String cardbackimage = card.getCardbackimage();
					if (cardbackimage != null) {
						pstmt.setString(parameterIndex++, cardbackimage);
					} else {
						pstmt.setNull(parameterIndex++, java.sql.Types.VARCHAR);
					}
					String frontHtml = card.getFrontHtml();
					if (frontHtml != null) {
						pstmt.setString(parameterIndex++, frontHtml);
					} else {
						pstmt.setNull(parameterIndex++, java.sql.Types.VARCHAR);
					}
					String backHtml = card.getBackHtml();
					if (backHtml != null) {
						pstmt.setString(parameterIndex++, backHtml);
					} else {
						pstmt.setNull(parameterIndex++, java.sql.Types.VARCHAR);
					}
				}
				for (int i = 0; i < dbSupportedClaims.size(); i++) {
					DbSupportedClaim claim = dbSupportedClaims.get(i);
					int sqlType = java.sql.Types.OTHER;
					if (claim.columnType.indexOf("varChar") > -1) {
						sqlType = java.sql.Types.VARCHAR;
					} else if (claim.columnType.indexOf("int") > -1) {
						sqlType = java.sql.Types.INTEGER;
					}
					String valueStr = card.getClaim(claim.uri);
					if (valueStr != null) {
						if (sqlType == java.sql.Types.VARCHAR) {
							pstmt.setString(parameterIndex++, valueStr);
						} else if (sqlType == java.sql.Types.INTEGER) {
							pstmt.setInt(parameterIndex++, Integer.valueOf(valueStr));
						} else {
							throw new StorageException("database type " + claim.columnType + " is not supported by the current implementation");
						}
					} else {
						pstmt.setNull(parameterIndex++, sqlType);
					}
				}

				pstmt.executeUpdate();

				{
					PreparedStatement account_cardsPStmt = null;
					try {
						account_cardsPStmt = conn
								.prepareStatement("insert into account_cards values (?, ?)");
						account_cardsPStmt.setString(1, username);
						account_cardsPStmt.setString(2, card.getCardId());
						// System.out.println(
						// "insert into account_cards values ('" + username +
						// "', '" + card.getCardId() +"')");
						account_cardsPStmt.executeUpdate();
						account_cardsPStmt.close();
					} finally {
						if (account_cardsPStmt != null) {
							account_cardsPStmt.close();
						}
					}
				}

				conn.commit();

			} catch (SQLException e) {

				// TODO - add an exception pattern
				System.out.println("Card creation failed");
				e.printStackTrace();

			} finally {
				if (pstmt != null) {
					pstmt.close();
				}
				conn.commit();

			}

		} catch (SQLException e) {
			e.printStackTrace(); // To change body of catch statement use File |
									// Settings | File Templates.
		} 

	}

	public List getCards(String username) {
		if (conn == null) {
			startup();
		}

		Vector cardIds = new Vector();
		PreparedStatement pstmt = null;
		try {
			pstmt = conn.prepareStatement("SELECT * FROM account_cards where username = ?");

			try {
				pstmt.setString(1, username);
				ResultSet rs = pstmt.executeQuery();
				while (rs.next()) {
					String id = rs.getString(2);
					cardIds.add(id);
				}
				rs.close();
				pstmt.close();
				conn.commit();
			} catch (SQLException e) {

				// eat the exception for now
				// TODO - add an exception pattern
				e.printStackTrace();

			} finally {
				pstmt.close();
				conn.commit();

			}

		} catch (SQLException e) {
			e.printStackTrace(); // To change body of catch statement use File |
									// Settings | File Templates.
		}

		return cardIds;

	}

	public ManagedCard getCard(String cardid) {
		if (conn == null) {
			startup();
		}

		ManagedCard card = null;
		PreparedStatement pstmt = null;
		try {
			pstmt = conn
					.prepareStatement("SELECT * FROM cards where cardid = ?");
			try {

				pstmt.setString(1, cardid);
				ResultSet rs = pstmt.executeQuery();
				int columnIndex = 1;
				while (rs.next()) {

					card = new ManagedCard(rs.getString(columnIndex++));
					card.setCardName(rs.getString(columnIndex++));
					card.setCardVersion(rs.getInt(columnIndex++));
					String timeissued = rs.getString(columnIndex++);
					System.out.println("CardStorageEmbeddedImpl getCard: timeissued=" + timeissued);
					card.setTimeIssued(timeissued);
					String timeexpired = rs.getString(columnIndex++);
					System.out.println("CardStorageEmbeddedImpl getCard: timeexpired=" + timeexpired);
					card.setTimeExpires(timeexpired);

					if (version > 1) {
						// introduced "requireStrongRecipientIdentity int" and
						// " requireAppliesTo int" with version 2
						int requireStrongRecipientIdentity = rs
								.getInt(columnIndex++);
						card
								.setRequireStrongRecipientIdentity(requireStrongRecipientIdentity != 0);
						int requireAppliesTo = rs.getInt(columnIndex++);
						card.setRequireAppliesTo(requireAppliesTo != 0);
					}

					if (version > 2) {
						String cardfrontimage = rs.getString(columnIndex++);
						card.setCardfrontimage(cardfrontimage);
						String cardbackimage = rs.getString(columnIndex++);
						card.setCardbackimage(cardbackimage);
						String frontHtml = rs.getString(columnIndex++);
						card.setFrontHtml(frontHtml);
						String backHtml = rs.getString(columnIndex++);
						card.setBackHtml(backHtml);
					}

					List<DbSupportedClaim> dbSupportedClaims = supportedClaimsImpl
							.dbSupportedClaims();
					for (int i = 0; i < dbSupportedClaims.size(); i++) {
						DbSupportedClaim claim = dbSupportedClaims.get(i);
						String value = rs.getString(columnIndex++);
						String uri = claim.uri;
						if (uri.indexOf('?') > 0) {
							System.out.println("cardId:" + cardid
									+ " dynamic claim:" + value);
							card.setClaim(uri, value);
						} else {
							if ((value != null) && (!"".equals(value))
									&& (!"null".equals(value))) {
								System.out.println("cardId:" + cardid
										+ " static claim:" + value);
								card.setClaim(uri, value);
							}
						}
					}
				}
				rs.close();
				pstmt.close();
				conn.commit();
			} catch (SQLException e) {

				// eat the exception for now
				// TODO - add an exception pattern
				e.printStackTrace();

			} finally {
				pstmt.close();
				conn.commit();

			}

		} catch (SQLException e) {
			e.printStackTrace(); // To change body of catch statement use File |
									// Settings | File Templates.
		}

		return card;

	}

	public void shutdown() {
		if (conn == null)
			return;

		try {
			conn.close();
			System.out.println("Embedded CardDB shutdown");
		} catch (SQLException e) {
			e.printStackTrace();
		}

	}

	public int getVersion() {
		if (conn == null) {
			startup();
		}
		try {
			if (conn.isClosed()) {
				startup();
			}
		} catch (SQLException e) {}
		return version;
	}

	/*
	 * public static void main(String[] args) {
	 * 
	 * CardStorage storage = new CardStorageEmbeddedDBImpl(); storage.startup();
	 * storage.addAccount("cmort1", "password"); boolean authn =
	 * storage.authenticate("cmort", "password1"); System.out.println(authn);
	 * 
	 * 
	 * XSDDateTime issued = new XSDDateTime(); XSDDateTime expires = new
	 * XSDDateTime(525600);
	 * 
	 * 
	 * ManagedCard card = new ManagedCard(); card.setGivenName("cmort");
	 * card.setSurname("motimore"); card.setEmailAddress("cmort@xmldap.org");
	 * card.setCardName("My Card"); card.setTimeIssued(issued.getDateTime());
	 * card.setTimeExpires(expires.getDateTime()); storage.addCard("cmort",
	 * card);
	 * 
	 * List cardIds = storage.getCards("cmort"); Iterator ids =
	 * cardIds.iterator(); while (ids.hasNext()){ String cardId = (String)
	 * ids.next(); ManagedCard thisCard = storage.getCard(cardId);
	 * System.out.println(thisCard.getCardId()); }
	 * 
	 * 
	 * 
	 * storage.shutdown();
	 * 
	 * }
	 */

}
