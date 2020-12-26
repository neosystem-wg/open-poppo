package jp.co.neosystem.wg.poppo.util;

import org.springframework.util.StringUtils;

public final class PoppoUtil {
	private PoppoUtil() {
	}

	public static String cutString(String str, int length) {
		if (StringUtils.isEmpty(str)) {
			return "";
		}
		if (str.length() <= length) {
			return str;
		}
		return str.substring(0, length);
	}

	public static String booleanToString(Boolean b) {
		if (b == null) {
			return "0";
		}
		return (b == false) ? "0" : "1";
	}
}
