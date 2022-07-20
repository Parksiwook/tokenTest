package com.token.commons.Jwt;


import com.token.domains.users.application.dto.UserRequest;
import com.token.domains.users.domain.UsersEntity;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
@Service
public class TokenUtils {

  private final String SECRET_KEY = "secretKey";
  private final String REFRESH_KEY = "refreshKey";
  private final String DATA_KEY = "userId";

  public String a = null;

  public String generateJwtToken(UsersEntity usersEntity) {
    return Jwts.builder()
        .setSubject(usersEntity.getUserId()) // 토큰 용도
        .setHeader(createHeader()) //Headers 설정
        .setClaims(createClaims(usersEntity)) // Claims 설정
        .setExpiration(createExpireDate(1000 * 60 * 5))//토큰 만료시간 설정
        .signWith(SignatureAlgorithm.HS256, createSigningKey(SECRET_KEY)) //대칭키 이용 , 서명 알고리즘
        .compact(); //토큰생성
  }

  public String saveRefreshToken(UsersEntity usersEntity) {
    return Jwts.builder()
        .setSubject(usersEntity.getUserId()) //토큰 용도
        .setHeader(createHeader()) //Headers 설정
        .setClaims(createClaims(usersEntity))// Claims 설정
        .setExpiration(createExpireDate(1000 * 60 * 10))//토큰 만료시간 설정
        .signWith(SignatureAlgorithm.HS256, createSigningKey(REFRESH_KEY))//서명 알고리즘
        .compact();//토큰생성
  }



  public boolean isValidToken(String token) {
    System.out.println("isValidToken is : " +token);
    try {
      Claims accessClaims = getClaimsFormToken(token);
      System.out.println("Access token: " + accessClaims.getExpiration());
      System.out.println("Access userId: " + accessClaims.get("userId"));
      a = (String) accessClaims.get("userId");

      return true;
    } catch (ExpiredJwtException exception) {
      System.out.println("Token UserID : " + exception.getClaims().getSubject());
      return false;
    } catch (JwtException exception) {
      System.out.println("Token Tampered");
      return false;
    } catch (NullPointerException exception) {
      System.out.println("Token null");
      return false;
    }
  }
  public boolean isValidRefreshToken(String token) {
    try {
      Claims accessClaims = getClaimsToken(token);

      System.out.println("Access token: " + accessClaims.getExpiration());
      System.out.println("Access userIdd: " + accessClaims.get("userId"));
      a = (String) accessClaims.get("userId");

      return true;
    } catch (ExpiredJwtException exception) {
      System.out.println("TokenUserID : " + exception.getClaims().getSubject());
      return false;
    } catch (JwtException exception) {
      System.out.println("Token");
      return false;
    } catch (NullPointerException exception) {
      System.out.println("Token null");
      return false;
    }
  }


  private Date createExpireDate(long expireDate) {
    long curTime = System.currentTimeMillis();
    return new Date(curTime + expireDate);
  }

  private Map<String, Object> createHeader() {
    Map<String, Object> header = new HashMap<>();

    header.put("typ", "ACCESS_TOKEN");
    header.put("alg", "HS256");
    header.put("regDate", System.currentTimeMillis());

    return header;
  }

  private Map<String, Object> createClaims(UsersEntity usersEntity) {
    Map<String, Object> claims = new HashMap<>();
    claims.put(DATA_KEY, usersEntity.getUserId());
    return claims;
  }

  private Key createSigningKey(String key) {
    byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(key);
    return new SecretKeySpec(apiKeySecretBytes, SignatureAlgorithm.HS256.getJcaName());
  }

  private Claims getClaimsFormToken(String token) {
    return Jwts.parser()
        .setSigningKey(DatatypeConverter.parseBase64Binary(SECRET_KEY))
        .parseClaimsJws(token)
        .getBody();
  }
  private Claims getClaimsToken(String token) {
    return Jwts.parser()
            .setSigningKey(DatatypeConverter.parseBase64Binary(REFRESH_KEY))
            .parseClaimsJws(token)
            .getBody();
  }
}
