package com.cg.jawt.controller;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.HashMap;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
@RestController

public class JwtController {

	@PostMapping("/post")
	public String SignInJwt(@RequestBody Map<String, Object> payload) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException{
         Map<String , Object> maps= new HashMap<String , Object>();
         String iss=(String) payload.get("issuer");
         String sub=(String) payload.get("subject");
         String id=(String) payload.get("id");
         String aud=(String) payload.get("audience");
         
		String jksPassword = "susmitha";
        
        KeyStore ks  = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream("C:\\Users\\SUSPUPPA\\Downloads\\OpenSSL\\bin\\pkcs.jks"), jksPassword.toCharArray());
        Key key = ks.getKey("1", jksPassword.toCharArray());
        String token = Jwts.builder()
        		.setIssuer(iss)
                .setSubject(sub)
                .setAudience(aud)
                .setId(id)  
                .signWith(SignatureAlgorithm.RS512, key)
                .compact();
		  return  token;
	}
	
	  @GetMapping("/get")
	public Claims Validate(@RequestBody Map<String ,Object> token) throws Exception{
    PublicKey publicKey = loadPublicKey("C:\\Users\\SUSPUPPA\\Downloads\\OpenSSL\\bin\\certificate_pub.crt");
    String token1= (String) token.get("token");
    Jws<Claims> x = Jwts.parser()
    	.setSigningKey(publicKey)
       .parseClaimsJws(token1);
	  return x.getBody();
}
	
public static PublicKey loadPublicKey(String filename)
           throws Exception
        {
           CertificateFactory cf = CertificateFactory.getInstance("X.509");
           Certificate cert = cf.generateCertificate(new FileInputStream(filename));
           PublicKey Val = cert.getPublicKey();
           return Val;
        }
	
}

