package com.example.user_service.service.impl;

import com.example.user_service.dto.*;
import com.example.user_service.entity.RefreshToken;
import com.example.user_service.entity.User;
import com.example.user_service.enums.Role;
import com.example.user_service.exception.EmailAlreadyExistsException;
import com.example.user_service.exception.ResourceNotFoundException;
import com.example.user_service.exception.UserBlockedException;
import com.example.user_service.repository.UserRepository;
import com.example.user_service.security.JwtService;
import com.example.user_service.security.RefreshTokenService;
import com.example.user_service.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    @Override
    public ResponseEntity<ApiResponseDTO> createUser(UserResponseDTO.UserCreateDTO userCreateDTO) {
        if (userRepository.existsByEmail(userCreateDTO.getEmail())) {
            throw new EmailAlreadyExistsException("Email Already Exists");
        }

        User newUser = new User();

        newUser.setEmail(userCreateDTO.getEmail());
        newUser.setPassword(passwordEncoder.encode(userCreateDTO.getPassword()));
        newUser.setFirstName(userCreateDTO.getFirstName());
        newUser.setLastName(userCreateDTO.getLastName());
        newUser.setImageUrl(userCreateDTO.getImageUrl());
        newUser.setRole(Role.CUSTOMER);
        newUser.setPhoneNumber(userCreateDTO.getPhoneNumber());

        userRepository.save(newUser);

        UserResponseDTO userResponseDTO = UserResponseDTO.builder()
                .firstName(newUser.getFirstName())
                .lastName(newUser.getLastName())
                .email(newUser.getEmail())
                .phoneNumber(newUser.getPhoneNumber())
                .imageUrl(newUser.getImageUrl())
                .role(newUser.getRole())
                .createdAt(newUser.getCreatedAt())
                .build();

        ApiResponseDTO apiResponseDTO = ApiResponseDTO.builder()
                .message("Successfully Created User")
                .status(HttpStatus.CREATED)
                .data(userResponseDTO)
                .build();

        return new ResponseEntity<>(apiResponseDTO, HttpStatus.CREATED);
    }

    @Override
    public ResponseEntity<ApiResponseDTO> login(LoginRequestDTO loginRequestDTO) {

        User user = userRepository.findByEmail(loginRequestDTO.getEmail())
                .orElseThrow(() -> new ResourceNotFoundException("Email Not Found"));

        if (user.isBlocked()) {
            throw new UserBlockedException("Blocked");
        }

        if (!passwordEncoder.matches(
                loginRequestDTO.getPassword(),
                user.getPassword())) {
            throw new UserBlockedException("Invalid password");
        }

        String accessToken = jwtService.generateAccessToken(
                String.valueOf(user.getUserID()),
                user.getRole().name()
        );

        RefreshToken refreshToken =
                refreshTokenService.createRefreshToken(user);

        LoginResponseDTO loginResponse =
                LoginResponseDTO.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken.getToken())
                        .userId(user.getUserID())
                        .firstName(user.getFirstName())
                        .email(user.getEmail())
                        .role(user.getRole().name())
                        .build();

        ApiResponseDTO apiResponseDTO = ApiResponseDTO.builder()
                .message("Login successful")
                .status(HttpStatus.OK)
                .data(loginResponse)
                .build();

        return new ResponseEntity<>(apiResponseDTO, HttpStatus.OK);
    }

    @Override
    public ResponseEntity<ApiResponseDTO> refreshAccessToken(String refreshToken) {

        RefreshToken storedToken = refreshTokenService.verifyRefreshToken(refreshToken);

        refreshTokenService.revokeToken(storedToken.getToken());

        User user = storedToken.getUser();

        if (user.isBlocked()) {
            throw new UserBlockedException(
                    "User account is blocked"
            );
        }

        String newAccessToken =
                jwtService.generateAccessToken(
                        String.valueOf(user.getUserID()),
                        user.getRole().name()
                );


        LoginResponseDTO loginResponseDTO = LoginResponseDTO.builder()
                        .accessToken(newAccessToken)
                        .refreshToken(refreshTokenService.createRefreshToken(user))
                        .userId(user.getUserID())
                        .firstName(user.getFirstName())
                        .email(user.getEmail())
                        .role(user.getRole().name())
                        .build();

        ApiResponseDTO apiResponseDTO = ApiResponseDTO.builder()
                .message("access token refreshed")
                .status(HttpStatus.OK)
                .data(loginResponseDTO)
                .build();

        return new ResponseEntity<>(apiResponseDTO, HttpStatus.OK);
    }

    @Override
    public ResponseEntity<ApiResponseDTO> logout(String refreshToken) {
        refreshTokenService.revokeToken(refreshToken);

        ApiResponseDTO apiResponseDTO = ApiResponseDTO.builder()
                .message("Logout successful")
                .status(HttpStatus.OK)
                .data(null)
                .build();

        return new ResponseEntity<>(apiResponseDTO, HttpStatus.OK);
    }

    }

