package jp.co.neosystem.wg.poppo.constants;

public enum SearchType {
	/** 完全一致 */
	MATCH,

	/** 前方一致 */
	START_WITH,

	/** 後方一致 */
	END_WITH,

	/** 部分一致 */
	PARTIAL_MATCH,
}
