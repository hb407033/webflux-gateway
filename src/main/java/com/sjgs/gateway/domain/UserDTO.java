package com.sjgs.gateway.domain;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.time.Instant;
import java.util.Set;

public class UserDTO {
    public static final String LOGIN_REGEX = "^[_.@A-Za-z0-9-]*$";
    private Long id;
    @NotBlank
    @Pattern(
        regexp = "^[_.@A-Za-z0-9-]*$"
    )
    @Size(
        min = 1,
        max = 50
    )
    private String login;
    @Size(
        max = 50
    )
    private String firstName;
    @Size(
        max = 50
    )
    private String lastName;
    @Email
    @Size(
        min = 5,
        max = 254
    )
    private String email;
    @Size(
        max = 256
    )
    private String imageUrl;
    private boolean enabled = false;
    @Size(
        min = 2,
        max = 6
    )
    private Boolean isEnabled;
    private String langKey;
    private String createdBy;
    private Instant createdDate;
    private String lastModifiedBy;
    private Instant lastModifiedDate;
    private String telephone;
    private Set<String> authorities;

    public UserDTO() {
    }

    public UserDTO(UaaUser user) {
        this.id = user.getId();
        this.login = user.getLogin();
        this.firstName = user.getFirstName();
        this.lastName = user.getLastName();
        this.email = user.getEmail();
        this.enabled = user.getEnabled();
        this.imageUrl = user.getImageUrl();
        this.langKey = user.getLangKey();

        this.telephone = user.getTelephone();
    }
}
