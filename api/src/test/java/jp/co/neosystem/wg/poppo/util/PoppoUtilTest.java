package jp.co.neosystem.wg.poppo.util;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class PoppoUtilTest {

	@Test
	public void test1() {
		String result = PoppoUtil.cutString("", 1);
		assertEquals("", result, "");
		return;
	}

	@Test
	public void test2() {
		String result = PoppoUtil.cutString("あいうえおかきくけこ", 5);
		assertEquals("あいうえお", result, "");
		return;
	}

	@Test
	public void test3() {
		String result = PoppoUtil.cutString("あいうえお", 5);
		assertEquals("あいうえお", result, "");
		return;
	}

	@Test
	public void test4() {
		String result = PoppoUtil.cutString("あ", 5);
		assertEquals("あ", result, "");
		return;
	}

	@Test
	public void test5() {
		String result = PoppoUtil.cutString(null, 1);
		assertEquals("", result, "");
		return;
	}

	@Test
	public void testBooleanToString1() {
		String result = PoppoUtil.booleanToString(null);
		assertEquals("0", result, "");
		return;
	}

	@Test
	public void testBooleanToString2() {
		String result = PoppoUtil.booleanToString(new Boolean(false));
		assertEquals("0", result, "");
		return;
	}

	@Test
	public void testBooleanToString3() {
		String result = PoppoUtil.booleanToString(new Boolean(true));
		assertEquals("1", result, "");
		return;
	}
}
