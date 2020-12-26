package jp.co.neosystem.wg.poppo.bean;

import jp.co.neosystem.wg.poppo.constants.UserColumn;
import org.apache.commons.lang3.StringUtils;

public class UserSortInfo {

	private final UserColumn columnName;

	private final boolean isDesc;

	public UserSortInfo(UserColumn columnName, boolean isDesc) {
		this.columnName = columnName;
		this.isDesc = isDesc;
	}

	public static UserSortInfo fromString(String str) {
		if (StringUtils.isEmpty(str)) {
			return null;
		}
		String tmp[] = str.split(":");
		if (tmp.length < 1) {
			return null;
		}
		UserColumn column = UserColumn.fromString(tmp[0]);
		if (column == null) {
			return null;
		}
		boolean isDesc = false;
		if (tmp.length >= 2) {
			String order = tmp[1];
			if ("DESC".equals(order)) {
				isDesc = true;
			}
		}
		return new UserSortInfo(column, isDesc);
	}

	@Override
	public String toString() {
		String tmp = (isDesc) ? "DESC" : "ASC";
		return columnName.getColumnName() + " " + tmp;
	}
}
