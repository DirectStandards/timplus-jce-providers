package org.directtruststandards.timplus.jceproviders.timplussplit;

import static org.junit.Assert.assertEquals;

import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

public class TIMPlusSplitProvider_constructorTest
{

	@Test
	public void testSingleProviderConstructor_assertProviders() throws Exception
	{
		final Provider assymetricProvider = new BouncyCastleProvider();
		
		final TIMPlusSplitProvider prov = new TIMPlusSplitProvider(assymetricProvider);
		
		assertEquals(Security.getProviders()[0], prov.getSymmetricProvider());
		assertEquals(assymetricProvider, prov.getAsymmetricProvider());
	}
}
