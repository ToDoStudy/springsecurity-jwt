package toyproject.springsecurityjwt.user;


import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import toyproject.springsecurityjwt.user.web.dto.UserRequestDto;
import toyproject.springsecurityjwt.user.web.dto.UserResponseDto;
import toyproject.springsecurityjwt.user.web.dto.UserSignupRequestDto;


@Transactional(readOnly = true) // 오직 읽기만 가능하다.
@RequiredArgsConstructor // final이 붙거나 @NotNull 이 붙은 필드의 생성자를 자동 생성해주는 롬복 어노테이션
@Service
public class UserService{


    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // 회원가입
    @Transactional
    public UserResponseDto signup(UserSignupRequestDto userSignupRequestDto){
        if(userRepository.existsByEmail(userSignupRequestDto.getEmail())){
            throw new RuntimeException("이미 가입되어 있는 유저입니다.");
        }

        // 회원가입시키기 위해 비밀번호를 암호로 바꿔서 저장한다.
        User user = userSignupRequestDto.toUser(passwordEncoder);
        return UserResponseDto.of(userRepository.save(user));
    }

    // 로그인한 사용자가 있는지 확인
    public UserResponseDto findUserInfoById(Long userId){
        return userRepository.findById(userId)
                .map(UserResponseDto::of)
                .orElseThrow(() -> new RuntimeException("로그인 유저 정보가 없습니다."));
    }

    // 사용자 조회
    public UserResponseDto findUserInfoByEmail(String email){
        return userRepository.findByEmail(email)
                .map(UserResponseDto::of)
                .orElseThrow(() -> new RuntimeException("유저 정보가 없습니다."));
    }

}
