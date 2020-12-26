package jp.co.neosystem.wg.poppo.entity;

import java.io.Serializable;

public class AuthAttrPrimaryKey implements Serializable {
	private String poppoId;

	private String federatedIdType;

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
}
