package toyproject.springsecurityjwt.user.web.dto;


import toyproject.springsecurityjwt.user.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class UserResponseDto {
    private String email;

    public static UserResponseDto of(User user){
        return new UserResponseDto(user.getEmail());
    }
}
