/*
 * Copyright 2010-2013 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package com.intuit.s3encrypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.cli.*;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.ClasspathPropertiesFileCredentialsProvider;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.model.Bucket;
import com.amazonaws.services.s3.model.DeleteObjectRequest;
import com.amazonaws.services.s3.model.DeleteObjectsRequest;
import com.amazonaws.services.s3.model.EncryptionMaterials;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.ListObjectsRequest;
import com.amazonaws.services.s3.model.ObjectListing;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectSummary;

@SuppressWarnings("unused")
public class S3Encrypt {
	
	public static String keyname = "private";
	public static File key;
	public static final String CREATE_BUCKET = "create_bucket";
	@SuppressWarnings("static-access")
	public static final Option create_bucket =
	    OptionBuilder.hasArg(true)
	        .withArgName("bucket")
	        .isRequired(false)
	        .withDescription("create bucket")
	        .create(CREATE_BUCKET);

	public static final String CREATE_KEY = "create_key";
	@SuppressWarnings("static-access")
	public static final Option create_key =
	    OptionBuilder.withArgName("filename")
	    	.hasArg(false)
	        .isRequired(false)
	        .withDescription("creates key")
	        .create(CREATE_KEY);

	public static final String DELETE_BUCKET = "delete_bucket";
	@SuppressWarnings("static-access")
	public static final Option delete_bucket =
	    OptionBuilder.withArgName("bucket")
	    	.hasArg(true)
	        .isRequired(false)
	        .withDescription("delete bucket")
	        .create(DELETE_BUCKET);

	public static final String GET = "get";
	@SuppressWarnings("static-access")
	public static final Option get =
	    OptionBuilder.withArgName("bucket> <filename")
    		.withValueSeparator(' ')
    		.hasArgs(2)
	        .isRequired(false)
	        .withDescription("get bucket object")
	        .create(GET);

	public static final String INSPECT = "inspect";
	@SuppressWarnings("static-access")
	public static final Option inspect =
	    OptionBuilder.withArgName("bucket> <filename")
    		.withValueSeparator(' ')
    		.hasArgs(2)
	        .isRequired(false)
	        .withDescription("inspect bucket object")
	        .create(INSPECT);

	public static final String KEYFILE = "keyfile";
	@SuppressWarnings("static-access")
	public static final Option keyfile =
	    OptionBuilder.withArgName("keyfile")
    		.hasArgs(1)
	        .isRequired(false)
	        .withDescription("keyfile")
	        .create(KEYFILE);
	
	public static final String LIST_BUCKETS = "list_buckets";
	@SuppressWarnings("static-access")
	public static final Option list_buckets =
	    OptionBuilder.withArgName("bucket")
	    	.hasArg(false)
	        .isRequired(false)
	        .withDescription("list buckets")
	        .create(LIST_BUCKETS);

	public static final String LIST_OBJECTS = "list_objects";
	@SuppressWarnings("static-access")
	public static final Option list_objects =
	    OptionBuilder.withArgName("bucket")
        	.hasArg(true)
	        .isRequired(false)
	        .withDescription("list objects")
	        .create(LIST_OBJECTS);
	
	public static final String PUT = "put";
	@SuppressWarnings("static-access")
	public static final Option put =
	    OptionBuilder.withArgName("bucket> <filename")
	    	.withValueSeparator(' ')
	    	.hasArgs(2)
	        .isRequired(false)
	        .withDescription("put bucket filename")
	        .create(PUT);

	public static final String REMOVE = "remove";
	@SuppressWarnings("static-access")
	public static final Option remove =
	    OptionBuilder.withArgName("bucket> <filename")
    		.withValueSeparator(' ')
    		.hasArgs(2)
	        .isRequired(false)
	        .withDescription("remove bucket filename")
	        .create(REMOVE);
	
	public static final String ROTATE = "rotate";
	@SuppressWarnings("static-access")
	public static final Option rotate =
	    OptionBuilder.withArgName("bucket> <filename")
			.withValueSeparator(' ')
			.hasArgs(2)
	        .isRequired(false)
	        .withDescription("bucket filename key1 key2")
	        .create(ROTATE);
	
	public static final String ROTATEALL = "rotateall";
	@SuppressWarnings("static-access")
	public static final Option rotateall =
	    OptionBuilder.withArgName("bucket")
			.withValueSeparator(' ')
			.hasArgs(1)
	        .isRequired(false)
	        .withDescription("bucket key1 key2")
	        .create(ROTATEALL);
	
	public static final String ROTATEKEY = "rotateKey";
	@SuppressWarnings("static-access")
	public static final Option rotateKey =
	    OptionBuilder.withArgName("rotateKey")
			.hasArgs(1)
	        .isRequired(false)
	        .withDescription("rotateKey")
	        .create(ROTATEKEY);

	public static final String HELP = "help";
	@SuppressWarnings("static-access")
	public static final Option help =
	    OptionBuilder.isRequired(false)
	        .withDescription("print this help")
	        .create(HELP);
	
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        // create Options object
    	Options options = new Options();
        options.addOption(create_bucket);
        options.addOption(create_key);
        options.addOption(delete_bucket);
        options.addOption(get);
        options.addOption(help);
        options.addOption(inspect);
        options.addOption(keyfile);
        options.addOption(list_buckets);
        options.addOption(list_objects);
        options.addOption(put);
        options.addOption(remove);
        options.addOption(rotate);
        options.addOption(rotateall);
        options.addOption(rotateKey);
        
//      CommandLineParser parser = new GnuParser();
// 		Changed from above GnuParser to below PosixParser because I found code which allows for multiple arguments 
        PosixParser parser = new PosixParser();
        CommandLine cmd;
		try {
			cmd = parser.parse( options, args );
			Logger.getRootLogger().setLevel(Level.OFF);
			
			if(cmd.hasOption("help")) {
				HelpFormatter help = new HelpFormatter();
                System.out.println();
                help.printHelp("S3Encrypt", options);
                System.out.println();
                System.exit(1);
			}
			else if (cmd.hasOption("create_key")) {
				keyname = cmd.getOptionValue("keyfile");            	
            	createKeyFile(keyname);
            	key = new File(keyname);
            }
			else {
				if (cmd.hasOption("keyfile")) {
					keyname = cmd.getOptionValue("keyfile");
				}
				key = new File(keyname);
			}
			
			if (! (key.exists())) {
				System.out.println("Key does not exist or not provided");
				System.exit(1);
			}
			
//			AmazonS3 s3 = new AmazonS3Client(new ClasspathPropertiesFileCredentialsProvider());
			ClasspathPropertiesFileCredentialsProvider credentials = new ClasspathPropertiesFileCredentialsProvider(".s3encrypt");			
			EncryptionMaterials encryptionMaterials = new EncryptionMaterials(getKeyFile(keyname));
			AmazonS3EncryptionClient s3 = new AmazonS3EncryptionClient(credentials.getCredentials(), encryptionMaterials);
//		    Region usWest2 = Region.getRegion(Regions.US_WEST_2);
//		    s3.setRegion(usWest2);
        	
            if(cmd.hasOption("create_bucket")) {
            	String bucket = cmd.getOptionValue("create_bucket");
                System.out.println("Creating bucket " + bucket + "\n");
                s3.createBucket(bucket);
            }
            else if(cmd.hasOption("delete_bucket")) {
            	String bucket = cmd.getOptionValue("delete_bucket");
            	System.out.println("Deleting bucket " + bucket + "\n");
                s3.deleteBucket(bucket);
            }
            else if(cmd.hasOption("get")) {            	
            	String[] searchArgs = cmd.getOptionValues("get");
            	String bucket = searchArgs[0];
            	String filename = searchArgs[1];
            	getS3Object(cmd, s3, bucket, filename);
            }
            else if(cmd.hasOption("inspect")) {
            	String[] searchArgs = cmd.getOptionValues("inspect");
            	String bucket = searchArgs[0];
            	String filename = searchArgs[1];
            	String keyname = "encryption_key";
            	String metadata = inspectS3Object(cmd, s3, bucket, filename, keyname);
            	System.out.println(metadata);
            }
            else if(cmd.hasOption("list_buckets")) {
                System.out.println("Listing buckets");
                for (Bucket bucket : s3.listBuckets()) {
                    System.out.println(bucket.getName());
                }
                System.out.println();
            }
            else if(cmd.hasOption("list_objects")) {
            	String bucket = cmd.getOptionValue("list_objects");
            	System.out.println("Listing objects");
            	ObjectListing objectListing = s3.listObjects(new ListObjectsRequest().withBucketName(bucket));
            	for (S3ObjectSummary objectSummary : objectListing.getObjectSummaries()) {
            		System.out.println(objectSummary.getKey() + "  " +
            				"(size = " + objectSummary.getSize() + ")");
            	}
            	System.out.println();
            }
            else if(cmd.hasOption("put")) {
            	String[] searchArgs = cmd.getOptionValues("put");
            	String bucket = searchArgs[0];
            	String filename = searchArgs[1];
            	String metadataKeyname = "encryption_key";
            	String key = keyname;
            	putS3Object(cmd, s3, bucket, filename, metadataKeyname, key);
            }
            else if(cmd.hasOption("remove")) {
            	String[] searchArgs = cmd.getOptionValues("remove");
            	String bucket = searchArgs[0];
            	String filename = searchArgs[1];
                System.out.println("Removing object in S3 from BUCKET = " + bucket + " FILENAME = " + filename);
                s3.deleteObject(new DeleteObjectRequest(bucket, filename));
                System.out.println();
            }
            else if(cmd.hasOption("rotate")) {
            	String[] searchArgs = cmd.getOptionValues("rotate");
            	String bucket = searchArgs[0];
            	String filename = searchArgs[1];
            	String key1 = cmd.getOptionValue("keyfile");
            	String key2 = cmd.getOptionValue("rotateKey");
            	String metadataKeyname = "encryption_key";
            	System.out.println("Supposed to get object from here OPTION VALUE = " + bucket + " FILENAME = " + filename +" KEY1 = " + key1 + " KEY2 = " + key2 );
    			
            	EncryptionMaterials rotateEncryptionMaterials = new EncryptionMaterials(getKeyFile(key2));
    			AmazonS3EncryptionClient rotateS3 = new AmazonS3EncryptionClient(credentials.getCredentials(), rotateEncryptionMaterials);
    			
            	getS3Object(cmd, s3, bucket, filename);
    			putS3Object(cmd, rotateS3, bucket, filename, metadataKeyname, key2);
            }
            else if(cmd.hasOption("rotateall")) {
            	String[] searchArgs = cmd.getOptionValues("rotateall");
            	String bucket = searchArgs[0];
            	String key1 = searchArgs[1];
            	String key2 = searchArgs[2];
            	System.out.println("Supposed to rotateall here for BUCKET NAME = " + bucket + " KEY1 = " + key1 + " KEY2 = " + key2 );
            }
            else {
            	System.out.println("Something went wrong... ");
            	System.exit(1);
            }
              
		} catch (ParseException e) {
			e.printStackTrace();
		} catch (AmazonServiceException ase) {
            System.out.println("Caught an AmazonServiceException, which " +
            		"means your request made it " +
                    "to Amazon S3, but was rejected with an error response" +
                    " for some reason.");
            System.out.println("Error Message:    " + ase.getMessage());
            System.out.println("HTTP Status Code: " + ase.getStatusCode());
            System.out.println("AWS Error Code:   " + ase.getErrorCode());
            System.out.println("Error Type:       " + ase.getErrorType());
            System.out.println("Request ID:       " + ase.getRequestId());
        } catch (AmazonClientException ace) {
            System.out.println("Caught an AmazonClientException, which " +
            		"means the client encountered " +
                    "an internal error while trying to " +
                    "communicate with S3, " +
                    "such as not being able to access the network.");
            System.out.println("Error Message: " + ace.getMessage());
        }

    }
    
    public static void saveS3ObjectContent(S3Object obj, String path,
            String filename) throws IOException {
        InputStream stream = obj.getObjectContent();
        FileOutputStream fos = new FileOutputStream(path + "/" + filename);
        byte[] buffer = new byte[1024];
        int len;
        while ((len = stream.read(buffer)) != -1) {
            fos.write(buffer, 0, len);
        }
        fos.close();
    }

	private static KeyPair getKeyFile(String filename) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
    	File f = new File(filename);
    	if(f.exists()) { 
    		KeyPair myKeyPair = loadKeyPair(filename, "RSA");
    		return myKeyPair;
    	} else {
    		KeyPair myKeyPair = createKeyFile(filename);
    		return myKeyPair;
    	}
    }
    
	private static KeyPair createKeyFile(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		  
		  KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
		  keyGenerator.initialize(2048, new SecureRandom());
		  KeyPair myKeyPair = keyGenerator.generateKeyPair();
		  
		  PublicKey publicKey = myKeyPair.getPublic();
		  PrivateKey privateKey = myKeyPair.getPrivate();
		 
		  System.out.println("keys created... " + filename);
		  
		  saveKeyPair(filename, myKeyPair);
		  return myKeyPair;
	}

    public static void saveKeyPair(String filename, KeyPair keyPair)
            throws IOException {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Save public key to file.
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                publicKey.getEncoded());
        FileOutputStream keyfos = new FileOutputStream(filename + ".pub");
        keyfos.write(x509EncodedKeySpec.getEncoded());
        keyfos.close();

        // Save private key to file.
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                privateKey.getEncoded());
        keyfos = new FileOutputStream(filename);
        keyfos.write(pkcs8EncodedKeySpec.getEncoded());
        keyfos.close();

    }
    
    public static KeyPair loadKeyPair(String filename, String algorithm)
            throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException {
        // Read public key from file.
        FileInputStream keyfis = new FileInputStream(filename + ".pub");
        byte[] encodedPublicKey = new byte[keyfis.available()];
        keyfis.read(encodedPublicKey);
        keyfis.close();

        // Read private key from file.
        keyfis = new FileInputStream(filename);
        byte[] encodedPrivateKey = new byte[keyfis.available()];
        keyfis.read(encodedPrivateKey);
        keyfis.close();

        // Generate KeyPair from public and private keys.
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        return new KeyPair(publicKey, privateKey);

    }
    
    private static void putS3Object (CommandLine cmd, AmazonS3EncryptionClient s3, String bucket, String filename, String keyname, String key) {
    	String[] searchArgs = cmd.getOptionValues("put");
        System.out.println("Uploading a new object to S3 BUCKET = " + bucket + " FILENAME = " + filename);
        File file = new File(filename);
        PutObjectRequest request = new PutObjectRequest(bucket, filename, file);
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.addUserMetadata(keyname, key);
        request.setMetadata(metadata);
        s3.putObject(request);
        System.out.println();
    }
    
    private static void getS3Object (CommandLine cmd, AmazonS3EncryptionClient s3, String bucket, String filename) throws IOException {
    	System.out.println("Getting object from bucket BUCKET = " + bucket + " OBJECT = " + filename);
    	S3Object downloadedObject = s3
                .getObject(bucket, filename);
        saveS3ObjectContent(downloadedObject, "./", filename);
    }

    private static String inspectS3Object (CommandLine cmd, AmazonS3EncryptionClient s3, String bucket, String filename, String keyname) {
    	System.out.println("Supposed to inspect the BUCKET = " + bucket + " OBJECT = " + filename);
    	S3Object s3object = s3.getObject(new GetObjectRequest(bucket, filename));
    	String metadata = s3object.getObjectMetadata().getUserMetadata().get(keyname);
    	return metadata;
    }
}
