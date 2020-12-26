package jp.co.neosystem.wg.poppo.bean;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

public class ReqRegisterAuthHistory {

	@NotNull
	@Size(min = 1, max = 4)
	private String federatedIdType;

	private Boolean success;

	@Size(min = 0, max = 128)
	private String ipAddr;

	private String userAgent;

	public String getFederatedIdType() {
		return federatedIdType;
	}

	public void setFederatedIdType(String federatedIdType) {
		this.federatedIdType = federatedIdType;
	}

	public Boolean getSuccess() {
		return success;
	}

	public void setSuccess(Boolean success) {
		this.success = success;
	}

	public String getIpAddr() {
		return ipAddr;
	}

	public void setIpAddr(String ipAddr) {
		this.ipAddr = ipAddr;
	}

	public String getUserAgent() {
		return userAgent;
	}

	public void setUserAgent(String userAgent) {
		this.userAgent = userAgent;
	}
}
