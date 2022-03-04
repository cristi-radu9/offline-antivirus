import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class OfflineAntivirus {

	public static void storeFolderContent(String path, List<String> filesNames) {
		File folder = new File(path);
		if (folder.exists() && folder.isDirectory()) {
			File[] entries = folder.listFiles();
			for (File entry : entries) {
				if (entry.isDirectory()) {
					storeFolderContent(entry.getAbsolutePath(), filesNames);
				} else {
					filesNames.add(entry.getPath());
				}
			}
		}
	}

	public static byte[] getHashMAC(String inputFileName, byte[] secretKey, String algorithm)
			throws IOException, NoSuchAlgorithmException, InvalidKeyException {
		byte[] hashMac = null;

		File file = new File(inputFileName);
		if (!file.exists()) {
			throw new FileNotFoundException();
		}

		// init the Mac object
		Mac mac = Mac.getInstance(algorithm);
		mac.init(new SecretKeySpec(secretKey, algorithm));

		FileInputStream fis = new FileInputStream(file);
		BufferedInputStream bis = new BufferedInputStream(fis);

		byte[] buffer = new byte[1024];
		int noBytesFromFile = bis.read(buffer);

		while (noBytesFromFile != -1) {
			mac.update(buffer, 0, noBytesFromFile);
			noBytesFromFile = bis.read(buffer);
		}

		hashMac = mac.doFinal();

		bis.close();
		fis.close();

		return hashMac;
	}

	public static void statusUpdate(String route,String secret) throws InvalidKeyException, NoSuchAlgorithmException, IOException {
		List<String> filesPaths = new ArrayList<>();
		File entry = new File(route);

		if (entry.exists() && entry.isDirectory()) {
			storeFolderContent(entry.getAbsolutePath(), filesPaths);
		}

		File outputFile = new File("StatusUpdate.txt");
		if (!outputFile.exists()) {
			outputFile.createNewFile();
		}

		FileOutputStream fos = new FileOutputStream(outputFile);
		BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(fos));
		for (String filePath : filesPaths) {
			byte[] hmac = getHashMAC(filePath, secret.getBytes(), "HmacSHA1");
			bw.write(filePath);
			bw.newLine();
			bw.write(Util.getHex(hmac));
			bw.newLine();			
		}
		bw.close();
		fos.close();
	}
	
	public static void integrityCheck(String secret) throws IOException, InvalidKeyException, NoSuchAlgorithmException {
		BufferedReader reader;
		FileReader fr=new FileReader("StatusUpdate.txt");
		reader=new BufferedReader(fr);
		
		String path;
		String hmac;
		List<String> fileStatuses = new ArrayList<>();
		
		String line=reader.readLine();
		while(line!=null) {
			path=line;
			line=reader.readLine();
			hmac=line;
			
			byte[] newHmac=getHashMAC(path, secret.getBytes(), "HmacSHA1");
			byte[] oldHmac=Util.hexStringToByteArray(hmac);
			
			boolean areTheSame=true;
			for(int i=0;i<newHmac.length;i++) {
				if(newHmac[i]!=oldHmac[i]) {
					areTheSame=false;
				}
			}
			
			if(areTheSame) {
				fileStatuses.add(path+ " : It's Ok!");
			}else {
				fileStatuses.add(path+ " : It's Corrupted!");
			}
			
			line=reader.readLine();
		}
		fr.close();
		reader.close();
		
		DateTimeFormatter dtf = DateTimeFormatter.ofPattern("uuuu-MM-dd HH mm ss");
		LocalDateTime now = LocalDateTime.now();
		String time = dtf.format(now);
		String fName=String.format("Check-%s.txt",time);
		File outputFile = new File(fName);
		if (!outputFile.exists()) {
			outputFile.createNewFile();
		}

		FileOutputStream fos = new FileOutputStream(outputFile);
		BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(fos));
		for (String status : fileStatuses) {
			bw.write(status);
			bw.newLine();
			
		}
		bw.close();
		fos.close();
	}

	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, IOException {

		String route = "**Path to your playground**";
		
		System.out.println("*****Offline Antivirus******");
		System.out.println("Enter your secret: ");
		BufferedReader reader = new BufferedReader(
	            new InputStreamReader(System.in));
		
		String secret=reader.readLine();
		System.out.println("************");
		System.out.println("Please enter the mode of operation");
		System.out.println("Please be aware that are only 2 modes of operation Update or Check");
		System.out.println("Important! If it's the first time you call this app you first need to Update then Check!");
		System.out.println("Mode of operation: ");
		String operation=reader.readLine();
		
		if(operation.toLowerCase().equals("update")) {
			statusUpdate(route,secret);
			System.out.println("Update completed!");
		}
		
		if(operation.toLowerCase().equals("check")) {
			integrityCheck(secret);
			System.out.println("Integrity check completed! Check the file generated!");
		}
		
	}

}
