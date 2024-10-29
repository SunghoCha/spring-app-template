package com.app.global.config.auth;

import com.app.domain.user.User;
import com.app.domain.user.repository.UserRepository;
import com.app.global.config.auth.dto.OAuthAttributes;
import com.app.global.config.auth.dto.SessionUser;
import com.app.global.error.JsonSerializationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collections;

@RequiredArgsConstructor
@Service
public class CustomOauth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;
    private final HttpSession httpSession;
    private final ObjectMapper objectMapper;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        ClientRegistration registration = userRequest.getClientRegistration();
        String registrationId = registration.getRegistrationId();
        String userNameAttributeName = registration.getProviderDetails()
                .getUserInfoEndpoint()
                .getUserNameAttributeName();

        // registration이나 userNameAttributeName이 여기서만 쓰이는데 인자로 userRequest와 oAuth2User를 전달하는건 별로인가?
        // 이렇게 되면 dto가 단순한 역할을 넘어서는 느낌이라 이렇게 하는게 나을지도..
        OAuthAttributes attributes = OAuthAttributes.of(registrationId, userNameAttributeName, oAuth2User.getAttributes());

        User user = saveOrUpdate(attributes);
        String userJson = convertToJson(new SessionUser(user));
        httpSession.setAttribute("user", userJson);

        // 싱글톤으로 하면 불변이라 권한 추가 불가능함에 유의
        return new DefaultOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(user.getRoleKey())),
                attributes.getAttributes(),
                attributes.getNameAttributeKey());
    }

    private String convertToJson(SessionUser sessionUser) {
        String userJson;
        try {
            userJson = objectMapper.writeValueAsString(sessionUser);
        } catch (JsonProcessingException e) {
            throw new JsonSerializationException("JSON 직렬화 실패");
        }
        return userJson;
    }

    // 처음보는 방식의 로직. 단일쿼리 후 map. entity가 null이면 map은 실행되지 않음
    private User saveOrUpdate(OAuthAttributes attributes) {
        User user = userRepository.findByEmail(attributes.getEmail())
                .map(entity -> entity.update(attributes.getName(), attributes.getPicture()))
                .orElse(attributes.toEntity());

        return userRepository.save(user);
    }
}
