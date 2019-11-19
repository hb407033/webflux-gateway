//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package com.sjgs.gateway.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import java.io.Serializable;
import java.time.Instant;

@Data
public class UaaUser  implements Serializable {
    private static final long serialVersionUID = 1L;

    private Long id;

    private String login;

    private String password;

    private String firstName;

    private String lastName;

    private String email;

    private String imageUrl;

    private Boolean enabled;

    private String langKey;

    private String activationKey;

    private String resetKey;

    private Instant resetDate;

    private Instant lastLoginTime;

    private Integer loginFailCount;

    private String telephone;
    @ApiModelProperty("验证码发送时间")

    private Instant captchaSendTime;

    @ApiModelProperty("验证码")

    private String captcha;

    @JsonIgnoreProperties({"parent", "lastModifiedDate", "createdBy", "createdDate", "lastModifiedBy", "uaaDepartments", "namespace"})

    public UaaUser() {
    }

}
