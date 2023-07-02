/* Michael Kovalski 
 * CIS443 - Applied Cryptography
 * Final Project Implementation
 * 
 * This program has two modes of operation: Encryption and Decryption.
 * 
 * Encryption mode will ask the user to input a desired directory, and
 * ask the user for a password to encrypt that directory. Each file in
 * the given directory will be encrypted using AES-CFB-256 encryption,
 * and the source files will be deleted. A keystore file containing the
 * encryption keys and an ivstore file containing the encryption IVs
 * will also be created next to the encrypted files.
 * 
 * Decryption mode will ask the user to input a desired encrypted
 * directory, and will ask the user for the password that was previously
 * used to encrypt it. Each file in the given directory (except for the
 * keystore and ivstore files) will be decrypted using the AES-CFB-256 
 * algorithm. The encrypted versions of the files will be deleted, along
 * with the keystore and ivstore files.
 * 
 * Note: This program only works with files using the UTF-8 charset, like
 * most .txt or .bat files.
 * 
 */

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;


public class FinalProject {
	
	public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
		
    	KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    	keyGenerator.init(n);
    	SecretKey key = keyGenerator.generateKey();
    	return key;
    	
	}//SecretKey
    
    public static IvParameterSpec generateIv() {
    	
    	byte[] iv = new byte[16];
    	new SecureRandom().nextBytes(iv);
    	return new IvParameterSpec(iv);
        
    }//IvParameterSpec
    
    
    public static String byteToString(byte[] input) {
    	//String output = new String(input, StandardCharsets.UTF_8);
    	String output = Base64.getEncoder().encodeToString(input);
    	return output;
    }//byteToString
    
    public static byte[] stringToByte(String input) {
    	//byte[] output = input.getBytes(StandardCharsets.UTF_8);
    	byte[] output = Base64.getMimeDecoder().decode(input);
    	return output;
    }//stringTobyte
    
    public static File[] removeIvStoreFromList(File[] input, int ivIndex) {

        if (input == null || ivIndex < 0 || ivIndex >= input.length) {
            return input;
        }

        File[] output = new File[input.length - 1];
 
        for (int i = 0, z = 0; i < input.length; i++) {
            if (i == ivIndex) {
                continue;
            }
            output[z++] = input[i];
        }
        
        return output;
    }//removeIvStoreFromList
    
    public static String getIvFromIvStore(File ivStore, int d) {
    	// Get IV in the dth row of ivstore file, return the string of that row
    	String iv = "";
    	
    	try (Stream<String> lines = Files.lines(ivStore.toPath())) {
            iv = lines.skip(d).findFirst().get();
          }
          catch(IOException e){
            System.out.println(e);
          }
    	
    	return iv;
    }//getIvFromIvStore
    
    public static void encryptFile(String algorithm, SecretKey key, IvParameterSpec iv, File ivStore, File inputFile, File outputFile) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
    	
    	Cipher cipher = Cipher.getInstance(algorithm);
    	cipher.init(Cipher.ENCRYPT_MODE, key, iv);

    	// Read inputFile into a byte array
    	byte[] inputFileBytes = Files.readAllBytes(inputFile.toPath());
    	
    	// Encrypt input byte array
    	byte[] cipherText = cipher.doFinal(inputFileBytes);
    	
    	//Write cipherText to outputFile
    	BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile));
    	writer.write(byteToString(cipherText));
    	
    	// Append Base64 IV to end of IV file (include a newline probably)
    	BufferedWriter writerIV = new BufferedWriter(new FileWriter(ivStore,true));
    	writerIV.write(byteToString(iv.getIV()) + '\n');
    	
    	// Close writer
    	writer.close();
    	writerIV.close();
    	    
    }//encryptFile
    
    public static void decryptFile(String algorithm, SecretKey key, IvParameterSpec iv, String inputFileStr, File outputFile) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException {
    	
    	Cipher cipher = Cipher.getInstance(algorithm);
    	cipher.init(Cipher.DECRYPT_MODE, key, iv);

    	// Decrypt input file string
    	byte[] plainText = cipher.doFinal(stringToByte(inputFileStr));
    	
    	
    	//Write plainText to outputFile
    	BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile));
    	writer.write(new String(plainText));
    	
    	// Close writer
    	writer.close();
    	
    }//decryptFile
    
    
    public static void encryptDirectory(String directory) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, IOException, KeyStoreException, CertificateException {
    	// Load files from given input directory into an array
    	File directoryContainer = new File(directory);
    	File[] fileList = directoryContainer.listFiles();
    	
    	// Initialize keystore
    	KeyStore keystore = KeyStore.getInstance("JCEKS");
    	// Take in user password for keystore
    	System.out.println("\nYou will need to enter a password to encrypt this directory with.\nBe sure to remember it for later, or your files will be unrecoverable!\nEnter the password now:");
		BufferedReader passwordReader = new BufferedReader(new InputStreamReader(System.in));
    	String password_input = passwordReader.readLine();
    	// Initialize keystore with user input password
    	char[] keystorePassword = password_input.toCharArray();
    	keystore.load(null, keystorePassword);
    	// Write keystore to file
    	try (FileOutputStream keystoreStream = new FileOutputStream(directory + "keystore.jceks")) {
    		keystore.store(keystoreStream, keystorePassword);
    	}//try
    	// Load newly created keystore
    	FileInputStream keystoreInputStream = new FileInputStream(directory + "keystore.jceks");
    	keystore.load(keystoreInputStream, keystorePassword);
    	
    	
    	Integer keystoreEntryNumber = 0;
    	// Call encryptFile method on each file in array with a loop
    	for (int i = 0; i < fileList.length; i++) {
    		keystoreEntryNumber = i;
    		SecretKey key 		= generateKey(256);
    		IvParameterSpec iv 	= generateIv();
    		File inputFile 		= new File(directory + fileList[i].getName());
    		File outputFile 	= new File(directory + fileList[i].getName() + ".encrypted");
    		File ivStore		= new File(directory + "ivstore.ivstore");
    		outputFile.createNewFile();	//create output file if it doesn't exist
    		ivStore.createNewFile();	//create ivstore file if it doesn't exist
    		System.out.println("Encrypting " + String.valueOf(inputFile));
    		//System.out.println("Key is " + byteToString(key.getEncoded()));
    		encryptFile("AES/CFB/NoPadding", key, iv, ivStore, inputFile, outputFile);
    		// Write current key to keystore
    		KeyStore.SecretKeyEntry secret = new KeyStore.SecretKeyEntry(key);
    		KeyStore.ProtectionParameter password = new KeyStore.PasswordProtection(keystorePassword);
    		keystore.setEntry(keystoreEntryNumber.toString(), secret, password);
    	}//for
    	
    	// Write keystore to file
    	try (FileOutputStream keystoreStream = new FileOutputStream(directory + "keystore.jceks")) {
    		keystore.store(keystoreStream, keystorePassword);
    		keystoreStream.close();
    		keystoreInputStream.close();
    	}//try
    	
    	// After encryption, delete all files that don't end with '.encrypted' or '.ivstore' or '.jceks'
    	File[] fileListPostEnc = directoryContainer.listFiles();
		for (int i = 0; i < fileListPostEnc.length; i++) {
			if (!fileListPostEnc[i].getName().endsWith(".encrypted") && !fileListPostEnc[i].getName().endsWith(".ivstore") && !fileListPostEnc[i].getName().endsWith(".jceks")) {
				boolean deleted = new File(directory+fileListPostEnc[i].getName()).delete();
			}
		}//for
    	System.out.println("\nGiven directory has been successfully encrypted.");
    	return;
    }//encryptDirectory
    
    
    public static void decryptDirectory(String directory) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException {
    	// Load files from given input directory into an array
    	File directoryContainer = new File(directory);
    	
    	// Get list of all files in directory (not including ivstore or keystore)
    	File[] fileListWithIvStore = directoryContainer.listFiles();
    	int ivIndex = 0;
    	int keystoreIndex = 0;
    	for (int i = 0; i < fileListWithIvStore.length; i++) {
    		if (fileListWithIvStore[i].getName().equalsIgnoreCase("ivstore.ivstore")) {
    			ivIndex = i;
    		}
    	}
    	File[] fileListNoIvStillKeystore = removeIvStoreFromList(fileListWithIvStore, ivIndex);
    	for (int i = 0; i < fileListNoIvStillKeystore.length; i++) {
    		if (fileListNoIvStillKeystore[i].getName().equalsIgnoreCase("keystore.jceks")) {
    			keystoreIndex = i;
    		}
    	}
    	File[] fileList = removeIvStoreFromList(fileListNoIvStillKeystore, keystoreIndex);
    	

    	// Initialize keystore
    	KeyStore keystore = KeyStore.getInstance("JCEKS");
    	// Take in user password for keystore
    	System.out.println("\nPlease enter the password that was used to encrypt this directory:");
		BufferedReader passwordReader = new BufferedReader(new InputStreamReader(System.in));
    	String password_input = passwordReader.readLine();
    	// Initialize keystore with user input password
    	char[] keystorePassword = password_input.toCharArray();
    	// Load keystore
    	FileInputStream keystoreInputStream = new FileInputStream(directory + "keystore.jceks");
    	keystore.load(keystoreInputStream, keystorePassword);
    	
    	Integer keystoreEntryNumber = 0;
    	// Call decryptFile method on each file in array with a loop
    	for (int i = 0; i < fileList.length; i++) {
    		if (!fileList[i].getName().equalsIgnoreCase("ivstore.ivstore") && !fileList[i].getName().equalsIgnoreCase("keystore.jceks")) {	// Ignore ivstore file

    		keystoreEntryNumber = i;
        	
    		// Get key from keystore
    		KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(keystorePassword);
    		KeyStore.SecretKeyEntry secretKeyEnt = (KeyStore.SecretKeyEntry)keystore.getEntry(keystoreEntryNumber.toString(), protectionParam);
    		SecretKey key = secretKeyEnt.getSecretKey();
    			
        	
        	
        	// Get IV of current file from ivstore
        	File ivStore		= new File(directory + "ivstore.ivstore");
        	String iv = getIvFromIvStore(ivStore, i);
        	byte[] iv_bytes = stringToByte(iv);
    	    final IvParameterSpec iv_spec = new IvParameterSpec(iv_bytes);
        	
    		
    		// Get IV from last 24 characters in file, then delete those last 24 characters
    		BufferedReader reader = new BufferedReader(new FileReader(fileList[i]));
    		StringBuilder stringBuilder = new StringBuilder();
    		String line = null;
    		String ls = System.getProperty("line.separator");
    		while ((line = reader.readLine()) != null) {
    			stringBuilder.append(line);
    			stringBuilder.append(ls);
    		}
    		// delete the last new line separator
    		stringBuilder.deleteCharAt(stringBuilder.length() - 1);
    		reader.close();

    		String str = stringBuilder.toString();

    	    // Call decryptFile
    	    String outputFilename = String.valueOf(fileList[i].getName()).substring(0, fileList[i].getName().length()-10);
    		File outputFile 	= new File(directory + outputFilename);
    	    decryptFile("AES/CFB/NoPadding", key, iv_spec, str, outputFile);
    		}
    	}//for
    	
    	// Keystore file won't be deleted if this isn't closed
    	keystoreInputStream.close();
    	
    	// After decryption, delete all files that end with '.encrypted' or '.ivstore' or '.jceks'
    	File[] fileListPostDec = directoryContainer.listFiles();
		for (int i = 0; i < fileListPostDec.length; i++) {
			if (fileListPostDec[i].getName().endsWith(".encrypted") || fileListPostDec[i].getName().endsWith(".ivstore") || fileListPostDec[i].getName().endsWith(".jceks")) {
				boolean deleted = new File(directory+fileListPostDec[i].getName()).delete();
			}
		}//for
    	System.out.println("\nGiven directory has been successfully decrypted, program will now exit. Goobye!");
    	return;
    }//decryptDirectory

    
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InterruptedException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, KeyStoreException, CertificateException, UnrecoverableEntryException {
    	
    	// Print intro blurb
    	System.out.println("\n\n=============================================================================");
    	System.out.println("\nCIS 443 - Final Project");
    	System.out.println("Michael Kovalski, 01711761");
    	
    	// Take in user input choice in a loop
    	Integer choiceCheck = 0;
    	while (choiceCheck.equals(0))	{
    		System.out.println("\n......\n\nDo you wish to encrypt a directory or decrypt a directory? (Enter 'E' for encrypt, 'D' for decrypt, or 'Q' to quit.)");	// Ask user for operation mode input
    		BufferedReader inputReaderMain = new BufferedReader(new InputStreamReader(System.in));
        	String inputChoice = inputReaderMain.readLine();
        	
        	// Encrypt chosen
	    	if (inputChoice.equalsIgnoreCase("E"))	{
	    		// Ask user for directory input, provide example
	    		System.out.println("\n\n------------------------------------------------------------------------------");
	    		System.out.println("\nChosen method: Encryption. Please enter a directory to encrypt. For example: 'C:\\Users\\Kovalski\\Documents\\Files\\'");
	    		String inputDirectory = inputReaderMain.readLine();
	    		// Check if directory exists, else tell user it doesn't exist and restart loop
	    		Path directoryCheck = Paths.get(inputDirectory);
	    		if (Files.notExists(directoryCheck)) {
	    			System.out.println("\nError, given path does not exist.");
	    			TimeUnit.SECONDS.sleep(1);
	    		} else {
	    			//Put slash at end of directory if it doesn't exist
	    			if(inputDirectory.charAt(inputDirectory.length()-1)!=File.separatorChar)	{
	    				inputDirectory += File.separator;
	    			}
	    			System.out.println("\nBeginning directory encryption sequence...");
		    		encryptDirectory(inputDirectory);	// Do encrypt method on input directory
		    		choiceCheck = 1;	// Leave loop
	    		}//if-else
	    		
	    	// Decrypt chosen
	    	} else if (inputChoice.equalsIgnoreCase("D"))	{
	    		// Ask user for directory input, provide example
	    		System.out.println("\n\n------------------------------------------------------------------------------");
	    		System.out.println("\nChosen method: Decryption. Please enter a directory to decrypt. For example: 'C:\\Users\\Kovalski\\Documents\\Files\\'");
	    		String inputDirectory = inputReaderMain.readLine();
	    		// Check if directory exists, if not tell user it doesn't exist and restart loop
	    		Path directoryCheck = Paths.get(inputDirectory);
	    		if (Files.notExists(directoryCheck)) {
	    			System.out.println("\nError, given path does not exist.");
	    			TimeUnit.SECONDS.sleep(1);
	    		} else {
	    			//Put slash at end of directory if it doesn't exist
	    			if(inputDirectory.charAt(inputDirectory.length()-1)!=File.separatorChar)	{
	    				inputDirectory += File.separator;
	    			}
	    			System.out.println("\nBeginning directory decryption sequence...");
		    		decryptDirectory(inputDirectory);	// Do decrypt method on input directory
		    		choiceCheck = 1;	// Leave loop
	    		}//if-else
	    		
	    	// Quit chosen
	    	} else if (inputChoice.equalsIgnoreCase("Q"))	{
	    		System.out.println("\nProgram will now exit. Goodbye!");
	    		System.exit(0);	//Close program
	    		
	    	// Invalid input
	    	} else {
	    		System.out.println("Invalid input, please try again.");	// Retry user input, show warning message
	    		TimeUnit.SECONDS.sleep(1);
	    	}//if-else
    	}//loop

    	
    	// Print outro blurb
    	System.out.println("\nProgram has finished execution. Goodbye!");
    	System.exit(0);
        
    }//main
    
}//FinalProject