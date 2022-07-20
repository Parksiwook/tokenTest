package com.token.commons.Jwt;

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

// JWT(Json Web Token)구조 - 헤더(Header). 내용(Payload). 서명(Signature)
@RequiredArgsConstructor
@Service
public class TokenUtils {

  private final String SECRET_KEY = "secretKey";
  private final String REFRESH_KEY = "refreshKey";
  private final String DATA_KEY = "userId";
  public String user_id = null;

  // HS256 : 대칭키 알고리즘 / 2개 이상의 영역에서 키 값 공유 (RS256 : 비대칭형 알고리즘 / 공개키와 개인키 2개의 키를 활용)
  // 원본 메시지가 변하면 그 해시값도 변하는 해싱의 특징을 활용하며 메시지의 변조 여부를 확인하여 무결성 및 기밀성을 제공하는 기술
  public String generateJwtToken(UsersEntity usersEntity) {
    return Jwts.builder()
        .setHeader(createHeader())                      // header 지정
        .setClaims(createClaims(usersEntity))           // payload에 들어 갈 claim 등록
        .setSubject(usersEntity.getUserId())
        .setExpiration(createExpireDate(1000 * 60 * 1)) // 토큰 만료 시간
        .signWith(SignatureAlgorithm.HS256, createSigningKey(SECRET_KEY)) // 해싱 알고리즘과 secret 키 설정
        .compact();     // jwt 토큰 생성
  }
  public String saveRefreshToken(UsersEntity usersEntity) {
    return Jwts.builder()
        .setHeader(createHeader())
        .setClaims(createClaims(usersEntity))
        .setSubject(usersEntity.getUserId())
        .setExpiration(createExpireDate(1000 * 60 * 2))
        .signWith(SignatureAlgorithm.HS256, createSigningKey(REFRESH_KEY))  // 해싱 알고리즘과 refresh 키 설정
        .compact();     // refresh 토큰 생성
  }



  public boolean isValidToken(String token) {
    System.out.println("isValidToken is : " +token);
    try {
      Claims accessClaims = getClaimsFormToken(token);
      System.out.println("Access token: " + accessClaims.getExpiration());
      System.out.println("Access userId: " + accessClaims.get("userId"));
      user_id = (String) accessClaims.get("userId");

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
//      a = (String) accessClaims.get("userId");

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
    header.put("alg", "HS256");           // signature 해싱하기 위한 알고리즘 지정(HS256) 해시 256 암호화
    header.put("regDate", System.currentTimeMillis());

    return header;
  }

  private Map<String, Object> createClaims(UsersEntity usersEntity) {   // payload
    Map<String, Object> claims = new HashMap<>();
    claims.put(DATA_KEY, usersEntity.getUserId());
    return claims;
  }

  private Key createSigningKey(String key) {
    byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(key);
    return new SecretKeySpec(apiKeySecretBytes, SignatureAlgorithm.HS256.getJcaName()); // signature 위변조 여부 확인
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
