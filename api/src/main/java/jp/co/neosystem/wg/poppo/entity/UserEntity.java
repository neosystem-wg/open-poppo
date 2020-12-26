package jp.co.neosystem.wg.poppo.entity;

import javax.persistence.*;

/**
 * ユーザ情報
 */
@Entity
@Table(name = "TBL_T_USER")
public class UserEntity {
	@Id
	@Column(name = "POPPO_ID")
	private String poppoId;

	@Column(name = "SCREEN_NAME")
	private String screenName;

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
}
