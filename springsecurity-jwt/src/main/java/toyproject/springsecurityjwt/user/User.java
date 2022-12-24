package toyproject.springsecurityjwt.user;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@NoArgsConstructor
@Getter @Setter
@Entity @Table(name="user")
public class User{

    // primary_key
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_no")
    private Long user_no;

    // 사용자 email, id
    private String email;

    // 사용자 이름
    private String name;

    // 비밀번호
    private String password;

    // 휴대폰
    private String phone;


    // 우편번호
    private int postcode;

    // 주소
    private String address;

    // 사용자, 관리자
    @Enumerated(EnumType.STRING)
    private Authority authority;

    private String receive;

    // 마지막 로그인?
    private String lastlogin;
    private String lastcp;


    // 로그인
    @Builder
    public User(String email, String password, Authority authority) {
        this.email = email;
        this.password = password;
        this.authority = authority;
    }

}
