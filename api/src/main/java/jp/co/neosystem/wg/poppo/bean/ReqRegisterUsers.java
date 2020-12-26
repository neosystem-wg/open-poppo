package jp.co.neosystem.wg.poppo.bean;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.List;

public class ReqRegisterUsers {
	private String poppoId;

	List<ServiceId> serviceId;

	@NotNull
	@Size(min = 1)
	List<FederatedId> federatedId;

	public String getPoppoId() {
		return poppoId;
	}

	public void setPoppoId(String poppoId) {
		this.poppoId = poppoId;
	}

	public List<ServiceId> getServiceId() {
		return serviceId;
	}

	public void setServiceId(List<ServiceId> serviceId) {
		this.serviceId = serviceId;
	}

	public List<FederatedId> getFederatedId() {
		return federatedId;
	}

	public void setFederatedId(List<FederatedId> federatedId) {
		this.federatedId = federatedId;
	}
}
