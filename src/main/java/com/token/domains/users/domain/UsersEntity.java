package com.token.domains.users.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import javax.persistence.*;

@Getter
@RequiredArgsConstructor
@Table(name = "users")
@Entity
@Repository
public class UsersEntity {

  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Id
  private Long id;
  private String userId;
  private String pw;
  private String name;
  private String age;
  private String area;
  private String school;
  private String blood;
  private String foot_size;
  private String travel;



  @Builder
  public UsersEntity(String userId, String pw, String name, String age, String area,
                     String school, String blood, String foot_size, String travel) {
    this.userId = userId;
    this.pw = pw;
    this.name = name;
    this.area = area;
    this.age = age;
    this.school = school;
    this.blood = blood;
    this.foot_size = foot_size;
    this.travel = travel;
  }



}
