package jp.co.neosystem.wg.poppo.bean;

import javax.validation.constraints.NotNull;

public class ReqUpdateUser {
	@NotNull
	private String screenName;

	public String getScreenName() {
		return screenName;
	}

	public void setScreenName(String screenName) {
		this.screenName = screenName;
	}
}
