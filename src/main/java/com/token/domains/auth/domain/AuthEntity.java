package com.token.domains.auth.domain;

import com.token.domains.users.domain.UsersEntity;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import javax.persistence.*;

// 토큰 관리 테이블(auth) 단방향 맵핑
@Getter
@RequiredArgsConstructor
@Table(name = "auth")
@Entity
public class AuthEntity {

  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Id
  private Long id;
  private String refreshToken;

  @ManyToOne
  @JoinColumn(name = "user_id")
  private UsersEntity usersEntity;

  @Builder
  public AuthEntity(String refreshToken, UsersEntity usersEntity) {
    this.refreshToken = refreshToken;
    this.usersEntity = usersEntity;
  }
  // refreshUpdate = DB에 저장, 사용하는 refreshToken이 만료되었을 때 DB에 업데이트되는 기능
  public void refreshUpdate(String refreshToken) {
    this.refreshToken = refreshToken;
  }
}
