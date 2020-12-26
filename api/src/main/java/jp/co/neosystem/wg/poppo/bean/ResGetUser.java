package jp.co.neosystem.wg.poppo.bean;

public class ResGetUser {

	private String poppoId;

	private String screenName;

	private FederatedId federatedId;

	private ServiceId serviceId;

	public String getPoppoId() {
		return poppoId;
	}

	public void setPoppoId(String poppoId) {
		this.poppoId = poppoId;
	}

	public String getScreenName() {
		return screenName;
	}

	public void setScreenName(String screenName) {
		this.screenName = screenName;
	}

	public FederatedId getFederatedId() {
		return federatedId;
	}

	public void setFederatedId(FederatedId federatedId) {
		this.federatedId = federatedId;
	}

	public ServiceId getServiceId() {
		return serviceId;
	}

	public void setServiceId(ServiceId serviceId) {
		this.serviceId = serviceId;
	}
}
