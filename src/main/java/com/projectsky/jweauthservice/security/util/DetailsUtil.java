package com.projectsky.jweauthservice.security.util;

import lombok.experimental.UtilityClass;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Map;

@UtilityClass
@Component
public class DetailsUtil {

    public static Map<String, Object> getDetails(Authentication authentication){
        @SuppressWarnings("unchecked")
        Map<String, Object> details = (Map<String, Object>) authentication.getDetails();
        if(details == null || !details.containsKey("jti")){
            throw new IllegalStateException("No jti in details");
        }
        return details;
    }
}
