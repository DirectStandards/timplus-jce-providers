package org.directtruststandards.timplus.jceproviders.SunPKCS11;

import static org.junit.Assert.assertTrue;

import java.security.KeyStore;
import java.util.Enumeration;

import org.apache.commons.lang3.StringUtils;
import org.directtruststandards.timplus.TestUtils;
import org.directtruststandards.timplus.common.crypto.MutableKeyStoreProtectionManager;
import org.directtruststandards.timplus.common.crypto.PKCS11Credential;
import org.directtruststandards.timplus.common.crypto.impl.BootstrappedPKCS11Credential;
import org.directtruststandards.timplus.common.crypto.impl.StaticPKCS11TokenKeyStoreProtectionManager;
import org.junit.Before;
import org.junit.Test;

public class eTokenProTLSTest 
{
	@Before
	public void setUp() throws Exception
	{
		
		if (!StringUtils.isEmpty(TestUtils.setupSafeNetToken()))
		{
			// clean out the token of all private keys
			final PKCS11Credential cred = new BootstrappedPKCS11Credential("1Kingpuff");
			
			final MutableKeyStoreProtectionManager mgr = new StaticPKCS11TokenKeyStoreProtectionManager(cred, "", "");
			
			KeyStore store = mgr.getKS();
			
			final Enumeration<String> aliases =  store.aliases();
			
			while (aliases.hasMoreElements())
			{
				final String alias = aliases.nextElement();
				
				store.deleteEntry(alias);
			}
			
			assertTrue(store.size() == 0);
			
		}
	}
	
	@Test
	public void testPKCS11TLSConnection() throws Exception
	{
		final String PKCS11Provider = TestUtils.setupSafeNetToken();
		
		if (StringUtils.isEmpty(PKCS11Provider))
		{
			
		}
	}
}
