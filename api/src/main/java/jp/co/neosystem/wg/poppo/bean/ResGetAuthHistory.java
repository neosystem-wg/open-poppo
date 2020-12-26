package jp.co.neosystem.wg.poppo.bean;

import jp.co.neosystem.wg.poppo.entity.AuthHistoryEntity;

import java.text.SimpleDateFormat;

public class ResGetAuthHistory {

	private String federatedIdType;

	private boolean success;

	private String ipAddr;

	private String userAgent;

	private String loginDate;

	public static ResGetAuthHistory create(AuthHistoryEntity entity) {
		ResGetAuthHistory res = new ResGetAuthHistory();

		res.federatedIdType = entity.getFederatedIdType();
		res.success = ("1".equals(entity.getLoginSuccessFlg()));
		res.ipAddr = entity.getIpAddr();
		res.userAgent = entity.getUserAgent();
		//SimpleDateFormat format = new SimpleDateFormat("yyyyMMddHHmmss");
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
		res.loginDate = format.format(entity.getCreateDate());
		return res;
	}

	public String getFederatedIdType() {
		return federatedIdType;
	}

	public void setFederatedIdType(String federatedIdType) {
		this.federatedIdType = federatedIdType;
	}

	public boolean isSuccess() {
		return success;
	}

	public void setSuccess(boolean success) {
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

	public String getLoginDate() {
		return loginDate;
	}

	public void setLoginDate(String loginDate) {
		this.loginDate = loginDate;
	}
}
