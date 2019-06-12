package net.jradius.client.auth;

import java.security.NoSuchAlgorithmException;

import net.jradius.client.RadiusClient;
import net.jradius.exception.RadiusException;
import net.jradius.packet.RadiusPacket;
import net.jradius.packet.attribute.AttributeDictionary;
import net.jradius.packet.attribute.AttributeFactory;
import net.jradius.packet.attribute.RadiusAttribute;

public abstract class RadiusAuthenticator 
{
	protected RadiusClient client;
    protected RadiusAttribute username;
    protected RadiusAttribute password;
    protected RadiusAttribute classAttribute;
    protected RadiusAttribute stateAttribute;

    public void setupRequest(RadiusClient c, RadiusPacket p) throws RadiusException, NoSuchAlgorithmException
    {
    	RadiusAttribute a;
        client = c;
        
        if (username == null)
        {
        	a = p.findAttribute(AttributeDictionary.USER_NAME);
            
        	if (a == null)
            	throw new RadiusException("You must at least have a User-Name attribute in a Access-Request");

        	username = AttributeFactory.copyAttribute(a, false);
        }
        
        if (password == null)
        {
        	a = p.findAttribute(AttributeDictionary.USER_PASSWORD);

        	if (a != null)
        	{
        		password = AttributeFactory.copyAttribute(a, false);
        	}
        }
    }

   
    public void processChallenge(RadiusPacket request, RadiusPacket challenge)  throws RadiusException, NoSuchAlgorithmException
    {
    	classAttribute = challenge.findAttribute(AttributeDictionary.CLASS);
        if (classAttribute != null)
        	request.overwriteAttribute(AttributeFactory.copyAttribute(classAttribute, false));
        
        stateAttribute = challenge.findAttribute(AttributeDictionary.STATE);
        if (stateAttribute != null)
        	request.overwriteAttribute(AttributeFactory.copyAttribute(stateAttribute, false));
    }
  
    public RadiusClient getClient()
    {
        return client;
    }
   
    public void setClient(RadiusClient client)
    {
        this.client = client;
    }
   
    protected byte[] getUsername()
    {
        return username == null ? null : username.getValue().getBytes();
    }

    protected byte[] getPassword()
    {
        if (password != null)
            return password.getValue().getBytes();
        
        return "".getBytes();
    }


	public void setUsername(RadiusAttribute userName) 
	{
		username = userName;
	}

	public void setPassword(RadiusAttribute cleartextPassword) 
	{
		password = cleartextPassword;
	}

    protected byte[] getClassAttribute()
    {
        return classAttribute == null ? null : classAttribute.getValue().getBytes();
    }

    protected byte[] getStateAttribute()
    {
        return stateAttribute == null ? null : stateAttribute.getValue().getBytes();
    }
 }
