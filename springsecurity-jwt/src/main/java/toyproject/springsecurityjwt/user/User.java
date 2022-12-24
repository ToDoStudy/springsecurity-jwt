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

    // 사용자와 게시판 1:N
//    @OneToMany(mappedBy = "user")
//    public List<Board> boards = new ArrayList<>();
//
//    // 아파트 N : 1
//    @ManyToOne(fetch= FetchType.LAZY)
//    @JoinTable(name="apartuser",
//            joinColumns = {@JoinColumn(name = "user_no",referencedColumnName = "user_no")},
//            inverseJoinColumns = {@JoinColumn(name = "apartment_no", referencedColumnName = "apartment_no")}
//    )
//    public Apartment apartment = new Apartment();

//
//    // ⬇️ UserDetails implements 상속 메서드들
//    // 사용자의 권한을 콜렉션 형태로 반환
//    // 단, 클래스 자료형은 GrantedAuthority를 구현해야한다.
//    // 참고자료 : https://shinsunyoung.tistory.com/78
//    @Override
//    public Collection<? extends GrantedAuthority> getAuthorities() {
//        Set<GrantedAuthority> roles = new HashSet<>();
//        for (String role : auth.split(",")) {
//            roles.add(new SimpleGrantedAuthority(role));
//        }
//        return roles;
//    }
//
//
//    // 사용자 id를 반환
//    @Override
//    public String getUsername() {
//        return id;
//    }
//
//    // 계정 만료 여부 반환
//    @Override
//    public boolean isAccountNonExpired() {
//        return true; // 만료되지 않았을 경우 true
//    }
//
//    @Override
//    public boolean isAccountNonLocked() {
//        return false;
//    }
//
//    @Override
//    public boolean isCredentialsNonExpired() {
//        return false;
//    }
//
//    @Override
//    public boolean isEnabled() {
//        return false;
//    }
}
