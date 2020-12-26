package jp.co.neosystem.wg.poppo.controller;

import jp.co.neosystem.wg.poppo.bean.*;
import jp.co.neosystem.wg.poppo.constants.SearchType;
import jp.co.neosystem.wg.poppo.constants.UserColumn;
import jp.co.neosystem.wg.poppo.entity.AuthAttrEntity;
import jp.co.neosystem.wg.poppo.entity.UserEntity;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.data.mongodb.core.query.CriteriaDefinition;
import org.springframework.data.mongodb.gridfs.GridFsCriteria;
import org.springframework.data.mongodb.gridfs.GridFsResource;
import org.springframework.data.mongodb.gridfs.GridFsTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;
import org.springframework.util.ResourceUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Controller
@Scope(value = WebApplicationContext.SCOPE_REQUEST)
public class Users {
	private static final Logger LOGGER = LoggerFactory.getLogger(Users.class);

	private static final int MAX_ICON_SIZE = 128 * 1024;

	@Autowired
	private NamedParameterJdbcTemplate jdbcTemplate;

	@Autowired
	private GridFsTemplate gridFsTemplate;

	@Autowired
	ResourceLoader resourceLoader;

	/**
	 * Bulk取得API
	 * */
	@RequestMapping(method = RequestMethod.POST, value = "/Bulk/Users")
	@ResponseBody
	public ResponseEntity<ResGetUsersBulk> getUsersBulk(@Validated @RequestBody ReqGetUsersBulk req) {

		MapSqlParameterSource param = new MapSqlParameterSource()
				.addValue("poppoId", req.getPoppoId());
		List<UserEntity> result = jdbcTemplate.query("SELECT POPPO_ID, SCREEN_NAME FROM TBL_T_POP_USER WHERE POPPO_ID IN (:poppoId)",
				param, new BeanPropertyRowMapper<UserEntity>(UserEntity.class));

		List<User> users = new ArrayList<>();

		for (UserEntity e : result) {
			User user = new User();
			user.setPoppoId(e.getPoppoId());
			user.setScreenName(e.getScreenName());
			users.add(user);
		}

		ResGetUsersBulk res = new ResGetUsersBulk();
		res.setUsers(users);
		return new ResponseEntity<>(res, HttpStatus.OK);
	}

	@RequestMapping(method = RequestMethod.GET, value = "/Users/{poppoId}/icon")
	public void downloadIcon(@PathVariable("poppoId") String poppoId, HttpServletResponse response)
			throws IOException {
		response.setStatus(200);

		GridFsResource resource = gridFsTemplate.getResource(poppoId);
		if (resource == null || !resource.exists()) {
			DefaultIconInfo info = DefaultIconInfo.create(poppoId);

			Resource rc = resourceLoader.getResource("classpath:" + info.getFileName());
			URL url = rc.getURL();

			response.setContentType(info.getContentType());

			int contentLength = (int) rc.contentLength();
			response.setContentLength(contentLength);

			LOGGER.info("download default icon (Content-Length: " + contentLength
					+ ", Content-Type: " + info.getContentType() + ")");

			OutputStream outputStream = response.getOutputStream();
			try (InputStream inputStream = url.openStream()) {
				responseIconImage(inputStream, outputStream);
			}
			return;
		}

		String contentType = resource.getContentType();
		if (StringUtils.isEmpty(contentType)) {
			contentType = "application/octet-stream";
		}
		response.setContentType(contentType);

		response.setContentLength((int) resource.contentLength());

		LOGGER.info("download icon (Content-Length: " + resource.contentLength()
				+ ", Content-Type: " + contentType + ")");

		OutputStream outputStream = response.getOutputStream();
		try (InputStream inputStream = resource.getInputStream()) {
			responseIconImage(inputStream, outputStream);
		}
		return;
	}

	void responseIconImage(InputStream inputStream, OutputStream outputStream) throws IOException {
		byte[] buf = new byte[4096];
		while (true) {
			int length = inputStream.read(buf);
			if (length == -1) {
				break;
			}
			outputStream.write(buf, 0, length);
		}
		return;
	}

	@RequestMapping(method = RequestMethod.POST, value = "/Users/{poppoId}/icon", headers="Content-Type=image/*")
	@ResponseBody
	public ResponseEntity<Object> uploadIcon(@PathVariable("poppoId") String poppoId,
											 @RequestHeader("Content-Type") String contentType,
											 @RequestHeader("Content-Length") Integer contentLength,
											 InputStream stream) {

		if (contentLength == null || contentLength > MAX_ICON_SIZE) {
			return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
		}

		LOGGER.info("upload icon (poppoId: " + poppoId
				+ ", Content-Type: " + contentType
				+ ", Content-Length: " + contentLength + ")");

		// 古いファイルの削除
		CriteriaDefinition definition = GridFsCriteria.whereFilename().is(poppoId);
		org.springframework.data.mongodb.core.query.Query query =
				new org.springframework.data.mongodb.core.query.Query(definition);
		gridFsTemplate.delete(query);

		gridFsTemplate.store(stream, poppoId, contentType);
		return new ResponseEntity<>(HttpStatus.OK);
	}

	/**
	 * 利用者情報登録API
	 * */
	@RequestMapping(method = RequestMethod.POST, value = "/Users",
			consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	@ResponseBody
	@Transactional
	public ResponseEntity<ResRegisterUsers> registerUser(@Validated @RequestBody ReqRegisterUsers req) {
		// TODO 面倒なのでとりあえず最初の1個だけ処理する
		// 検索
		FederatedId federatedId = req.getFederatedId().get(0);

		MapSqlParameterSource param = new MapSqlParameterSource()
				.addValue("federatedIdType", federatedId.getType())
				.addValue("federatedIdValue", federatedId.getValue());
		List<AuthAttrEntity> result = jdbcTemplate.query("SELECT POPPO_ID FROM TBL_T_POP_AUTH_ATTR WHERE FEDERATED_ID_TYPE = :federatedIdType and FEDERATED_ID_VALUE = :federatedIdValue",
				param, new BeanPropertyRowMapper<AuthAttrEntity>(AuthAttrEntity.class));
		AuthAttrEntity entity = (CollectionUtils.isEmpty(result)) ? null : result.get(0);

		ResRegisterUsers res = new ResRegisterUsers();
		if (entity == null || StringUtils.isEmpty(entity.getPoppoId())) {
			// 新規登録
			String poppoId = RandomStringUtils.randomAlphanumeric(16);

			Date now = new Date();
			final String createSystem = "api";
			param = new MapSqlParameterSource()
					.addValue("poppoId", poppoId)
					.addValue("createSystem", createSystem)
					.addValue("createDate", now);
			jdbcTemplate.update("insert into TBL_T_POP_USER (POPPO_ID, CREATE_SYSTEM, CREATE_DATE) values (:poppoId, :createSystem, :createDate)", param);

			param = new MapSqlParameterSource()
					.addValue("poppoId", poppoId)
					.addValue("federatedIdType", federatedId.getType())
					.addValue("federatedIdValue", federatedId.getValue())
					.addValue("createSystem", createSystem)
					.addValue("createDate", now);
			jdbcTemplate.update("insert into TBL_T_POP_AUTH_ATTR (POPPO_ID, FEDERATED_ID_TYPE, FEDERATED_ID_VALUE, CREATE_SYSTEM, CREATE_DATE) values (:poppoId, :federatedIdType, :federatedIdValue, :createSystem, :createDate)", param);

			res.setPoppoId(poppoId);
		} else {
			String poppoId = entity.getPoppoId();
			res.setPoppoId(poppoId);
		}
		LOGGER.info("poppoId: " + res.getPoppoId() + ", IDType: " + federatedId.getType() + ". IDValue: " + federatedId.getValue());
		return new ResponseEntity<ResRegisterUsers>(res, HttpStatus.OK);
	}

	/**
	 * 利用者情報更新API
	 * */
	@RequestMapping(method = RequestMethod.POST, value = "/Users/{poppoId}",
			consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	@ResponseBody
	@Transactional
	public ResponseEntity<ResRegisterUsers> updateUser(@PathVariable("poppoId") String poppoId, @Validated @RequestBody ReqUpdateUser req) {
		MapSqlParameterSource param = new MapSqlParameterSource()
				.addValue("poppoId", poppoId).addValue("screenName", req.getScreenName());

		jdbcTemplate.update("UPDATE TBL_T_POP_USER SET SCREEN_NAME = :screenName WHERE POPPO_ID = :poppoId", param);
		return new ResponseEntity<>(HttpStatus.OK);
	}

	/**
	 * 利用者取得API
	 * */
	@RequestMapping(method = RequestMethod.GET, value = "/Users/{poppoId}",
			produces = MediaType.APPLICATION_JSON_VALUE)
	@ResponseBody
	public ResponseEntity<ResGetUser> getUser(@PathVariable("poppoId") String poppoId) {
		MapSqlParameterSource param = new MapSqlParameterSource()
				.addValue("poppoId", poppoId);
		List<UserEntity> result = jdbcTemplate.query("SELECT SCREEN_NAME FROM TBL_T_POP_USER WHERE POPPO_ID = :poppoId",
				param, new BeanPropertyRowMapper<UserEntity>(UserEntity.class));
		if (CollectionUtils.isEmpty(result)) {
			// TODO エラーにするか要検討
			return new ResponseEntity<>(HttpStatus.OK);
		}

		// TODO 残りの項目を返す
		ResGetUser res = new ResGetUser();
		res.setPoppoId(poppoId);
		res.setScreenName(result.get(0).getScreenName());

		return new ResponseEntity<ResGetUser>(res, HttpStatus.OK);
	}

	/**
	 * 利用者検索API
	 * */
	@RequestMapping(method = RequestMethod.GET, value = "/Users", produces = MediaType.APPLICATION_JSON_VALUE)
	@ResponseBody
	public ResponseEntity<ResSearchUsers> searchUser(@RequestParam("q") String screenName, @RequestParam(value = "sort", required = false) List<String> sort,
													 @RequestParam(value = "offset", required = false) Integer offset,
													 @RequestParam(value = "limit", required = false) Integer limit, @RequestParam(value = "type", required = false) String type) {

		// 検索タイプ
		SearchType searchType = SearchType.START_WITH;
		if ("0".equals(type)) {
			searchType = SearchType.START_WITH;
		} else if ("1".equals(type)) {
			searchType = SearchType.END_WITH;
		} else if ("2".equals(type)) {
			searchType = SearchType.MATCH;
		} else if ("3".equals(type)) {
			searchType = SearchType.PARTIAL_MATCH;
		}

		// ソート
		ArrayList<UserSortInfo> sortInfoList = new ArrayList<>();
		if (CollectionUtils.isEmpty(sort)) {
			UserSortInfo tmp = new UserSortInfo(UserColumn.CREATE_DATE, true);
			sortInfoList.add(tmp);
		}  else {
			for (String str : sort) {
				LOGGER.info(str);
			}
			for (String str : sort) {
				UserSortInfo tmp = UserSortInfo.fromString(str);
				if (tmp == null) {
					LOGGER.info("不正なorder by指定: " + str);
					return new ResponseEntity<>( HttpStatus.BAD_REQUEST);
				}
				sortInfoList.add(tmp);
			}
		}

		List<UserEntity> result = searchUserByScreenName(searchType, screenName, limit, offset, sortInfoList);

		if (CollectionUtils.isEmpty(result)) {
			ResSearchUsers res = new ResSearchUsers();
			res.setTotal(0);
			return new ResponseEntity<>(res, HttpStatus.OK);
		}

		List<User> users = new ArrayList<>();
		for (UserEntity entity : result) {
			User u = new User();
			u.setPoppoId(entity.getPoppoId());
			u.setScreenName(entity.getScreenName());
			users.add(u);
		}
		ResSearchUsers res = new ResSearchUsers();
		res.setUsers(users);
		res.setTotal(result.size());
		return new ResponseEntity<>(res, HttpStatus.OK);
	}

	List<UserEntity> searchUserByScreenName(SearchType type, String screenName, Integer reqLimit, Integer reqOffset, List<UserSortInfo> sortInfoList) {

		if (screenName == null) {
			screenName = "";
		}
		if (type == SearchType.MATCH) {
			// 完全一致
			MapSqlParameterSource param = new MapSqlParameterSource()
					.addValue("screenName", screenName);
			return jdbcTemplate.query("SELECT * FROM TBL_T_POP_USER WHERE SCREEN_NAME = :screenName",
					param, new BeanPropertyRowMapper<UserEntity>(UserEntity.class));

		}
		String word = screenName
			.replace("$", "$$")
			.replace("%", "$%")
			.replace("_", "$_");

		int limit = (reqLimit == null) ? 10 : reqLimit;
		int offset = (reqOffset == null) ? 0 : reqOffset;
		switch (type) {
		case START_WITH:
			// 前方一致
			word += "%";
			LOGGER.info("前方一致検索: " + word);
			break;
		case END_WITH:
			word = "%" + word;
			LOGGER.info("後方一致検索: " + word);
			break;
		case PARTIAL_MATCH:
			word = "%" + word + "%";
			LOGGER.info("部分一致検索: " + word);
			break;
		default:
			return null;
		}

		String query = String.format("SELECT * FROM TBL_T_POP_USER WHERE SCREEN_NAME like :word {escape '$'} ORDER BY %s limit :limit offset :offset",
				concatSortInfo(sortInfoList));
		MapSqlParameterSource param = new MapSqlParameterSource()
				.addValue("limit", limit)
				.addValue("word", word)
				.addValue("offset", offset);
		return jdbcTemplate.query(query,
				param, new BeanPropertyRowMapper<UserEntity>(UserEntity.class));
	}

	private String concatSortInfo(List<UserSortInfo> sortInfoList) {
		if (CollectionUtils.isEmpty(sortInfoList)) {
			return "";
		}
		StringBuilder sb = new StringBuilder(sortInfoList.get(0).toString());
		for (int i = 1; i < sortInfoList.size(); ++i) {
			sb.append(", ");
			sb.append(sortInfoList.get(i).toString());
		}
		return sb.toString();
	}

	public static class DefaultIconInfo {
		private final String fileName;
		private final String contentType;

		private DefaultIconInfo(String fileName, String contentType) {
			this.fileName = fileName;
			this.contentType = contentType;
		}

		public static DefaultIconInfo create(String poppoId) {
			//int index = poppoId.hashCode() % 10;
			return new DefaultIconInfo("default_icon_01.jpg", "image/jpeg");
		}

		public File getFile()
				throws FileNotFoundException {
			return ResourceUtils.getFile(
					"classpath:" + fileName);
		}

		public String getFileName() {
			return fileName;
		}

		public String getContentType() {
			return contentType;
		}
	}
}
