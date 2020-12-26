package jp.co.neosystem.wg.poppo.constants;

public enum UserColumn {
	POPPO_ID("POPPO_ID"),
	CREATE_DATE("CREATE_DATE"),
	SCREEN_NAME("SCREEN_NAME");

	private final String columnName;

	private UserColumn(String columnName) {
		this.columnName = columnName;
	}

	public static UserColumn fromString(String columnName) {
		for (UserColumn u : values()) {
			if (u.getColumnName().equals(columnName)) {
				return u;
			}
		}
		return null;
	}

	public String getColumnName() {
		return columnName;
	}
}
