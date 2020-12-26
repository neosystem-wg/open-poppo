package jp.co.neosystem.wg.poppo.bean;

import jp.co.neosystem.wg.poppo.entity.AuthHistoryEntity;

import java.util.ArrayList;
import java.util.List;

public class ResGetAuthHistoryList {

	private List<ResGetAuthHistory> history;

	private Integer total;

	public void add(AuthHistoryEntity entity) {
		if (history == null) {
			history = new ArrayList<>();
		}
		history.add(ResGetAuthHistory.create(entity));
		return;
	}

	public List<ResGetAuthHistory> getHistory() {
		return history;
	}

	public void setHistory(List<ResGetAuthHistory> history) {
		this.history = history;
	}

	public Integer getTotal() {
		return total;
	}

	public void setTotal(Integer total) {
		this.total = total;
	}
}
