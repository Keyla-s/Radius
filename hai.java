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
    protected RadiusAttribute userName;
    protected RadiusAttribute password;
    protected RadiusAttribute classAttribute;
    protected RadiusAttribute stateAttribute;
	
String getSharedSecret(InetAddress client);

String getUserPassword(String userName);
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

public abstract void processRequest(RadiusPacket p) throws RadiusException, NoSuchAlgorithmException;
	
RadiusPacket accessRequestReceived(AccessRequest request, InetAddress client);
RadiusPacket accountingRequestReceived(AccountingRequest request, InetAddress client);

RadiusServer server = new MyRadiusServer();
server.start(true, true);
server.stop();
