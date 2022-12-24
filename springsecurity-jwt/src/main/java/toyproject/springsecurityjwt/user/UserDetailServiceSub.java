package toyproject.springsecurityjwt.user;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class UserDetailServiceSub implements UserDetailsService {

    private final UserRepository userRepository;

    // user의 id를 통해 user에 대한 인증정보를 가져온다.
    // username -> email
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // findByEmail의 username을 통해 현재 사용자의 정보를 발급 받고
        // createUserDetails을 통해 UserDetail 객체로 만들어서 리턴
        // 없으면 예외처리
        return userRepository.findByEmail(username)
                .map(this::createUserDetails)
                .orElseThrow(() -> new UsernameNotFoundException(username + " 는 db에서 찾을 수 없습니다."));
    }

    // DB에 User 값이 존재한다면 UserDetails 객체로 만들어서 리턴한다.
    private UserDetails createUserDetails(User user){
        // 사용자 권한을 발급받는다.
        // 이전 사용자가 ROLE_USER이면 이에 해당하는 권한
        // - ROLE_USER, ROLE_ADMIN
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(user.getAuthority().toString());

        return new org.springframework.security.core.userdetails.User(
                String.valueOf(user.getUser_no()),
                user.getPassword(),
                Collections.singleton(grantedAuthority)
        );
    }
}
