package org.directtruststandards.timplus.jceproviders.timplussplit;

import java.security.Provider;
import java.security.Security;
import java.util.Map;

/**
 * Wrapper/shim class that splits asymmetric and symmetric key operations between two different JCE providers.  This
 * is generally used when for a PKC11 token is introduced for asymmetric crypto operations.  This is necessary because the underlying 
 * Java TLS engine only uses a single JCE provider (the first
 * provider listed in the JVM security configuration) for all operations.  If an PKCS11 token is listed first, then all symmetric key operations will also
 * be performed on the token.  This may be acceptable (and even required) in some cases, but other deployments may wish to still perform symmetric key operations
 * in JVM memory using the default JCE provider.  This is mainly for performance reasons.
 * <br><br>
 * This provider allows the system to configure a PKCS11 token JCE provider and a symmetric key operation provider.  If a symmetric operation provider is not selected,
 * this provider uses the default JVM JCE provider.
 * 
 * @author Greg Meyer
 *
 * @since 1.0
 */
public class TIMPlusSplitProvider extends Provider
{
	private static final long serialVersionUID = 1135665199018860009L;

	protected final Provider asymmetricProvider;
	
	protected final Provider symmetricProvider;
	
	public TIMPlusSplitProvider(Provider asymmetricProvider)
	{
		this(asymmetricProvider, null);
	}
	
	public TIMPlusSplitProvider(Provider asymmetricProvider, Provider symmetricProvider)
	{
		super("TIMPLUSSPLITPROVIDER", 1.0, "TIMPlus Split Operations Security Provider Wrapper");
		
		this.asymmetricProvider = asymmetricProvider;
		
		if (symmetricProvider != null)
		{
			this.symmetricProvider = symmetricProvider;
		}
		else
		{
			/*
			 * Get the first provider in the security provider list
			 */
			final Provider[] providers = Security.getProviders();
			
			// realistically, this should probably never happen, but coding for it just in case
			if (providers == null || providers.length == 0)  
				throw new IllegalStateException("No default JCE providers have been configured");
			
			this.symmetricProvider = providers[0];
		}
		
		/*
		 * Pull in all of the settings from the default provider first
		 * Leave out any Cipher RSA or Cipher EC entries
		 */
		for (Map.Entry<Object,Object> entry : this.symmetricProvider.entrySet())		
		{
			final String key = entry.getKey().toString().toUpperCase();
			if (!(key.startsWith("CIPHER.RSA") || key.startsWith("CIPHER.EC")))
				this.put(entry.getKey(), entry.getValue());
		}
		
		/*
		 * Pull in asymmetric classes
		 */
		for (Map.Entry<Object,Object> entry : this.asymmetricProvider.entrySet()) 
		{			
			final String key = entry.getKey().toString().toUpperCase();
			if ((key.startsWith("CIPHER.RSA") || key.startsWith("CIPHER.EC")))
				this.put(entry.getKey(), entry.getValue());
		}
	}
	
	public Provider getSymmetricProvider()
	{
		return this.symmetricProvider;
	}
	
	public Provider getAsymmetricProvider()
	{
		return this.asymmetricProvider;
	}
}
