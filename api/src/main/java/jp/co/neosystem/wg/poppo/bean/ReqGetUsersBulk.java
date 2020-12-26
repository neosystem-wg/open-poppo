package jp.co.neosystem.wg.poppo.bean;

import javax.validation.constraints.Size;
import java.util.List;

public class ReqGetUsersBulk {
	@Size(min = 1, max = 100)
	private List<String> poppoId;

	public List<String> getPoppoId() {
		return poppoId;
	}

	public void setPoppoId(List<String> poppoId) {
		this.poppoId = poppoId;
	}
}
