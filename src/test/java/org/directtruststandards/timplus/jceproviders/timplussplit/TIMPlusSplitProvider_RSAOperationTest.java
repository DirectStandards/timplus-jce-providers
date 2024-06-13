package org.directtruststandards.timplus.jceproviders.timplussplit;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.operator.OutputEncryptor;
import org.directtruststandards.timplus.common.cert.CertUtils;
import org.directtruststandards.timplus.common.cert.X509CertificateEx;
import org.directtruststandards.timplus.common.crypto.CryptoUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class TIMPlusSplitProvider_RSAOperationTest
{
	String provName;
	
	@Before
	public void setUp() throws Exception
	{
		CryptoUtils.registerJCEProviders();
		
		final Provider prov = new TIMPlusSplitProvider(new BouncyCastleProvider());
		
		provName = prov.getName();
		
		Security.addProvider(prov);
	}
	
	@After
	public void tearDown()
	{
		
		Security.removeProvider(provName);
	}
	
	@Test
	public void testRSAEncryptDecrypt() throws Exception
	{
		byte[] testBytes = {(byte)0x00, (byte)0x45, (byte)0xac, (byte)0xab};
		
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		
		keyPairGenerator.initialize(2048);
		
		final KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		/*
		 * encrypt
		 */
		final Cipher encrypt=Cipher.getInstance("RSA/ECB/PKCS1Padding", provName);
		
		encrypt.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
		
		final byte[] encryptedMessage = encrypt.doFinal(testBytes);
		
		/*
		 * decrypt
		 */
		final Cipher decrypt=Cipher.getInstance("RSA/ECB/PKCS1Padding", provName);
		
		decrypt.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
		
		final byte[] decryptedMessage = decrypt.doFinal(encryptedMessage);
		
		assertTrue(Arrays.equals(testBytes, decryptedMessage));
		
	}
}
