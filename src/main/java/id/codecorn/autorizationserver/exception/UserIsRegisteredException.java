package id.codecorn.autorizationserver.exception;

public class UserIsRegisteredException extends Exception {

	public UserIsRegisteredException() {
	}

	public UserIsRegisteredException(String message) {
		super(message);
	}

	public UserIsRegisteredException(Throwable cause) {
		super(cause);
	}

	public UserIsRegisteredException(String message, Throwable cause) {
		super(message, cause);
	}

	public UserIsRegisteredException(String message, Throwable cause, boolean enableSuppression,
			boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

}
