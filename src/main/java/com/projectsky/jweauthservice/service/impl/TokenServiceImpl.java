package com.projectsky.jweauthservice.service.impl;

import com.projectsky.jweauthservice.config.props.*;
import com.projectsky.jweauthservice.enums.JwtPayload;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.projectsky.jweauthservice.event.TokenRevokedEvent;
import com.projectsky.jweauthservice.exception.JwtAuthenticationException;
import com.projectsky.jweauthservice.repository.TokenWhitelistRepository;
import com.projectsky.jweauthservice.security.util.DetailsUtil;
import com.projectsky.jweauthservice.service.TokenService;
import com.projectsky.jweauthservice.service.redis.RedisTokenStore;
import jakarta.annotation.PostConstruct;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;

@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private final KeysProperties keysProps;
    private final JwtClaimsProperties jwtClaimsProps;

    private byte[] hmacSecret;
    private RSAPrivateKey encryptionPrivate;
    private RSAPublicKey  encryptionPublic;

    private DefaultJWTClaimsVerifier<SecurityContext> jwtClaimsVerifier;

    private final ApplicationEventPublisher publisher;

    private final TokenWhitelistRepository whitelistRepository;
    private final RedisTokenStore redisTokenStore;

    /**
     * Простановка ключей
     * Настройка конфигурации Claims
     * */
    @PostConstruct
    public void init() {
        try {

            final KeyFactory keyFactoryRsa = KeyFactory.getInstance("RSA");

            // Декодирование base64 HS512 ключа
            hmacSecret = Base64.getDecoder().decode(keysProps.getHmac().getSecret());
            if (hmacSecret.length < 64) {
                throw new IllegalArgumentException("HMAC secret must be at least 64 bytes for HS512");
            }

            // RSA ключи для JWE шифрования/расшифровки
            encryptionPrivate = (RSAPrivateKey) keyFactoryRsa.generatePrivate(
                    new PKCS8EncodedKeySpec(Base64.getDecoder().decode(keysProps.getEncrypt().getPrivateKey())));
            encryptionPublic = (RSAPublicKey) keyFactoryRsa.generatePublic(
                    new X509EncodedKeySpec(Base64.getDecoder().decode(keysProps.getEncrypt().getPublicKey())));

            // Конфигурация проверки Claims
            JWTClaimsSet expected = new JWTClaimsSet.Builder()
                    .issuer(jwtClaimsProps.getIssuer())
                    .audience(jwtClaimsProps.getAudience())
                    .build();

            // Необходимые в payload поля
            HashSet<String> required = new HashSet<>(jwtClaimsProps.getRequiredClaims());

            jwtClaimsVerifier = new DefaultJWTClaimsVerifier<>(expected, required);
            jwtClaimsVerifier.setMaxClockSkew(60); // допуск 60 секунд расхождения
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e){
            throw new IllegalArgumentException("key setup failed", e);
        }
    }

    /**
     * Генерация токена:
     *  Сборка claims
     *  Подпись общим секретом
     *  Шифрование результата (JWE, RSA-OAEP-256 + A256GCM) публичным ключом шифрования
     */
    @Override
    public String generateToken(String username, String role, Instant expiresAt) {
        try {

            String jti = UUID.randomUUID().toString(); // Уникальный ID токена
            Date now = new Date();

            // Сборка claims
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(username)
                    .claim(JwtPayload.ROLE.getValue(), role)
                    .jwtID(jti)
                    .issuer(jwtClaimsProps.getIssuer())
                    .audience(jwtClaimsProps.getAudience())
                    .issueTime(now)
                    .notBeforeTime(now)
                    .expirationTime(Date.from(expiresAt))
                    .build();

            // Подпись общим секретом
            JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.HS512)
                    .type(JOSEObjectType.JWT)
                    .keyID("sign-kid-1")
                    .build();

            SignedJWT signedJWT = new SignedJWT(jwsHeader, claims);
            signedJWT.sign(new MACSigner(hmacSecret));

            // Шифрование (JWE, RSA-OAEP-256 + A256GCM)
            JWEHeader jweHeader = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                    .type(JOSEObjectType.JWT)
                    .contentType("JWT")
                    .keyID("enc-kid-1")
                    .build();

            JWEObject jweObject = new JWEObject(jweHeader, new Payload(signedJWT.serialize()));
            jweObject.encrypt(new RSAEncrypter(encryptionPublic));

            return jweObject.serialize();
        } catch (JOSEException e) {
            throw new JwtAuthenticationException("Failed to generate token", e);
        }
    }

    /**
     * Валидация токена:
     *  Расшифровка JWE приватным ключом шифрования
     *  Проверка заголовков JWE
     *  Проверка подписи JWS (HS512)
     *  Проверка claims (exp/nbf/iss/aud/jti/role и тд) через Nimbus DefaultJWTClaimsVerifier
     */
    @Override
    public JWTClaimsSet decryptAndVerify(String token){
        try {

            // Расшифровка JWE токена
            JWEObject jweObject = JWEObject.parse(token);
            JWEHeader jweHeader = jweObject.getHeader();

            // Проверка на правильность заголовков
            if (!JWEAlgorithm.RSA_OAEP_256.equals(jweHeader.getAlgorithm())
                    || !EncryptionMethod.A256GCM.equals(jweHeader.getEncryptionMethod())
                    || !JOSEObjectType.JWT.equals(jweHeader.getType())
                    || (jweHeader.getContentType() == null || !"JWT".equals(jweHeader.getContentType()))) {
                throw new SecurityException("Unexpected JWE header");
            }

            jweObject.decrypt(new RSADecrypter(encryptionPrivate));

            // Получение JWS из JWE
            SignedJWT jwt = jweObject.getPayload().toSignedJWT();

            // Проверка заголовка и подписи JWS
            if (!JWSAlgorithm.HS512.equals(jwt.getHeader().getAlgorithm())
                    || !JOSEObjectType.JWT.equals(jwt.getHeader().getType())) {
                throw new SecurityException("Unexpected JWS header");
            }

            if (!jwt.verify(new MACVerifier(hmacSecret))) {
                throw new SecurityException("Invalid JWS signature");
            }

            // Проверка Claims на наличие полей в payload
            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            verifyClaimsWithNimbus(claims);
            return claims;
        } catch (JOSEException | ParseException e){
            throw new JwtAuthenticationException("Failed to parse or verify JWT", e);
        }
    }

    @Override
    @Transactional
    public void revokeToken() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()){
            throw new IllegalStateException("Authentication is not authenticated");
        }

        Map<String, Object> details = DetailsUtil.getDetails(authentication);

        String jti = (String) details.get("jti");
        publisher.publishEvent(new TokenRevokedEvent(jti));
    }

    @Override
    public boolean isTokenValid(JWTClaimsSet claims) {
        String jti = claims.getJWTID();
        Instant expiresAt = claims.getExpirationTime().toInstant();

        // Проверка на наличие в редисе
        if (redisTokenStore.isValid(jti, expiresAt)) {
            return true;
        }

        // Проверка на наличие в базе
        return whitelistRepository.findById(jti)
                .filter(t -> Instant.now().isBefore(t.getExpiresAt()))
                .map(t -> {
                    redisTokenStore.store(jti, t.getExpiresAt()); // Если нашли в базе - добавляем в редис
                    return true;
                })
                .orElse(false);
    }

    @Override
    public String extractJti(String token) {
        return decryptAndVerify(token).getJWTID();
    }

    @Override
    public Instant extractExpiration(String token) {
        return decryptAndVerify(token).getExpirationTime().toInstant();
    }

    private void verifyClaimsWithNimbus(JWTClaimsSet claims) {
        try{
            jwtClaimsVerifier.verify(claims, null);
        } catch (BadJWTException e){
            throw new JwtAuthenticationException("Invalid JWT claims", e);
        }

    }
}

