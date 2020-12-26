package jp.co.neosystem.wg.poppo.entity;

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name = "TBL_H_AUTH")
public class AuthHistoryEntity {

	@Id
	@Column(name = "HISTORY_ID")
	private Long historyId;

	@Column(name = "POPPO_ID")
	private String poppoId;

	@Column(name = "FEDERATED_ID_TYPE")
	private String federatedIdType;

	@Column(name = "LOGIN_SUCCESS_FLG")
	private String loginSuccessFlg;

	@Column(name = "IP_ADDR")
	private String ipAddr;

	@Column(name = "USER_AGENT")
	private String userAgent;

	@Column(name = "CREATE_DATE")
	private Date createDate;

	@Column(name = "CREATE_SYSTEM")
	private String createSystem;

	@Column(name = "UPDATE_DATE")
	private Date updateDate;

	@Column(name = "UPDATE_SYSTEM")
	private String updateSystem;

	public Long getHistoryId() {
		return historyId;
	}

	public void setHistoryId(Long historyId) {
		this.historyId = historyId;
	}

	public String getPoppoId() {
		return poppoId;
	}

	public void setPoppoId(String poppoId) {
		this.poppoId = poppoId;
	}

	public String getFederatedIdType() {
		return federatedIdType;
	}

	public void setFederatedIdType(String federatedIdType) {
		this.federatedIdType = federatedIdType;
	}

	public String getLoginSuccessFlg() {
		return loginSuccessFlg;
	}

	public void setLoginSuccessFlg(String loginSuccessFlg) {
		this.loginSuccessFlg = loginSuccessFlg;
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

	public Date getCreateDate() {
		return createDate;
	}

	public void setCreateDate(Date createDate) {
		this.createDate = createDate;
	}

	public String getCreateSystem() {
		return createSystem;
	}

	public void setCreateSystem(String createSystem) {
		this.createSystem = createSystem;
	}

	public Date getUpdateDate() {
		return updateDate;
	}

	public void setUpdateDate(Date updateDate) {
		this.updateDate = updateDate;
	}

	public String getUpdateSystem() {
		return updateSystem;
	}

	public void setUpdateSystem(String updateSystem) {
		this.updateSystem = updateSystem;
	}
}
