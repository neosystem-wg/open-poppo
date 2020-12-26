package jp.co.neosystem.wg.poppo.controller;

import jp.co.neosystem.wg.poppo.bean.ResValidationError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;

import java.sql.SQLException;

@ControllerAdvice
public class PoppoControllerAdvice {

	private static final Logger LOGGER = LoggerFactory.getLogger(PoppoControllerAdvice.class);

	@ExceptionHandler({MethodArgumentNotValidException.class})
	@ResponseBody
	public ResponseEntity<ResValidationError> handleValidationError(MethodArgumentNotValidException e) {
		LOGGER.info("バリデーションエラー(2): " + e.getBindingResult());
		//LOGGER.info("バリデーションエラー  (message: " + e.getMessage() + ", binding result: " + e.getBindingResult() + ")");

		StringBuilder message = new StringBuilder();

		BindingResult bindingResult = e.getBindingResult();
		if (bindingResult != null && bindingResult.getFieldError() != null) {
			FieldError fieldError = bindingResult.getFieldError();
			message.append("field: ").append(fieldError.getField());
			message.append(", messsage: ").append(fieldError.getDefaultMessage());
		}

		ResValidationError res = new ResValidationError();
		res.setErrorDescription(message.toString());
		return new ResponseEntity<>(res, HttpStatus.BAD_REQUEST);
	}

	@ExceptionHandler({SQLException.class})
	@ResponseBody
	public ResponseEntity<Object> handleMyException(SQLException e) {
		LOGGER.warn("SQLエラー: " + e.getMessage(), e);
		return new ResponseEntity<>(HttpStatus.SERVICE_UNAVAILABLE);
	}
}
