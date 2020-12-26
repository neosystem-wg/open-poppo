package jp.co.neosystem.wg.poppo.controller;

import jp.co.neosystem.wg.poppo.bean.*;
import jp.co.neosystem.wg.poppo.entity.AuthHistoryEntity;
import jp.co.neosystem.wg.poppo.util.PoppoUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.WebApplicationContext;

import java.util.Date;
import java.util.List;

@Controller
@Scope(value = WebApplicationContext.SCOPE_REQUEST)
public class AuthHistory {
	private static final Logger LOGGER = LoggerFactory.getLogger(AuthHistory.class);

	@Autowired
	private NamedParameterJdbcTemplate jdbcTemplate;

	private static final int MAX_USER_AGENT_LENGTH = 256;

	/**
	 * ログイン履歴記録
	 * */
	@RequestMapping(method = RequestMethod.POST, value = "/Users/{poppoId}/history")
	@ResponseBody
	@Transactional
	public ResponseEntity<Object> registerHistory(@PathVariable("poppoId") String poppoId, @Validated @RequestBody ReqRegisterAuthHistory req) {

		LOGGER.info("register auth history (poppoId: " + poppoId
				+ ", type: " + req.getFederatedIdType()
				+ ", success: " + req.getSuccess()
				+ ", IP address: " + req.getIpAddr()
				+ ", User-Agent: " + req.getUserAgent()
				+ ")");

		final String createSystem = "api";

		final String userAgent = PoppoUtil.cutString(req.getUserAgent(), MAX_USER_AGENT_LENGTH);

		MapSqlParameterSource param = new MapSqlParameterSource()
				.addValue("poppoId", poppoId)
				.addValue("federatedIdType", req.getFederatedIdType())
				.addValue("success", PoppoUtil.booleanToString(req.getSuccess()))
				.addValue("ipAddr", req.getIpAddr())
				.addValue("userAgent", userAgent)
				.addValue("createSystem", createSystem)
				.addValue("createDate", new Date())
				;

		jdbcTemplate.update(
				"insert into TBL_H_AUTH (POPPO_ID, FEDERATED_ID_TYPE, LOGIN_SUCCESS_FLG, IP_ADDR, USER_AGENT, CREATE_SYSTEM, CREATE_DATE) values "
				+ "(:poppoId, :federatedIdType, :success, :ipAddr, :userAgent, :createSystem, :createDate)",
				param
		);
		return new ResponseEntity<>(HttpStatus.OK);
	}

	@RequestMapping(method = RequestMethod.GET, value = "/Users/{poppoId}/history")
	@ResponseBody
	public ResponseEntity<ResGetAuthHistoryList> getHistory(@PathVariable("poppoId") String poppoId,
															@RequestParam(value = "offset", required = false) Integer offset,
															@RequestParam(value = "limit", required = false) Integer limit) {

		if (offset == null) {
			offset = 0;
		}
		if (limit == null || limit <= 0) {
			limit = 10;
		}

		ResGetAuthHistoryList response = new ResGetAuthHistoryList();

		MapSqlParameterSource param = new MapSqlParameterSource()
				.addValue("poppoId", poppoId)
				;
		Integer count = jdbcTemplate.queryForObject("SELECT count(1) FROM TBL_H_AUTH WHERE POPPO_ID = :poppoId", param, Integer.class);
		response.setTotal(count);

		param = new MapSqlParameterSource()
				.addValue("offset", offset)
				.addValue("limit", limit)
				.addValue("poppoId", poppoId)
				;
		List<AuthHistoryEntity> result = jdbcTemplate.query("SELECT * FROM TBL_H_AUTH WHERE POPPO_ID = :poppoId ORDER BY CREATE_DATE DESC LIMIT :limit OFFSET :offset",
				param, new BeanPropertyRowMapper<AuthHistoryEntity>(AuthHistoryEntity.class));
		if (CollectionUtils.isEmpty(result)) {
			return new ResponseEntity<>(response, HttpStatus.OK);
		}

		for (AuthHistoryEntity entity : result) {
			response.add(entity);
		}
		return new ResponseEntity<>(response, HttpStatus.OK);
	}
}