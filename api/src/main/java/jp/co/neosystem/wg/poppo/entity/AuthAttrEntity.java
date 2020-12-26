package jp.co.neosystem.wg.poppo.entity;

import javax.persistence.*;

@Entity
@Table(name = "TBL_T_AUTH_ATTR")
@IdClass(AuthAttrPrimaryKey.class)
public class AuthAttrEntity {
	@Id
	@Column(name = "POPPO_ID")
	private String poppoId;

	@Id
	@Column(name = "FEDERATED_ID_TYPE")
	private String federatedIdType;

	@Column(name = "FEDERATED_ID_VALUE")
	private String federatedIdValue;

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

	public String getFederatedIdValue() {
		return federatedIdValue;
	}

	public void setFederatedIdValue(String federatedIdValue) {
		this.federatedIdValue = federatedIdValue;
	}
}
