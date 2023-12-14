package org.keycloak.protocol.oid4vp;

import java.util.Objects;


public class ExpectedResult<T> {
    private final T expectedResult;
    private final String message;
    private Response response;

    public ExpectedResult(T expectedResult, String message) {
        this.expectedResult = expectedResult;
        this.message = message;
    }

    public ExpectedResult(T expectedResult, String message, Response response) {
        this.expectedResult = expectedResult;
        this.message = message;
        this.response = response;
    }

    public T getExpectedResult() {
        return expectedResult;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ExpectedResult<?> that = (ExpectedResult<?>) o;
        return Objects.equals(expectedResult, that.expectedResult) && Objects.equals(message, that.message) && Objects.equals(response, that.response);
    }

    @Override
    public String toString() {
        return "ExpectedResult{" +
                "expectedResult=" + expectedResult +
                ", message='" + message + '\'' +
                ", response=" + response +
                '}';
    }

    @Override
    public int hashCode() {
        return Objects.hash(expectedResult, message, response);
    }

    public String getMessage() {
        return message;
    }

    public Response getResponse() {
        return response;
    }

    public static class Response {
        private final int code;
        private final boolean success;

        public Response(int code, boolean success) {
            this.code = code;
            this.success = success;
        }

        public int getCode() {
            return code;
        }

        public boolean isSuccess() {
            return success;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Response response = (Response) o;
            return code == response.code && success == response.success;
        }

        @Override
        public String toString() {
            return "Response{" +
                    "code=" + code +
                    ", success=" + success +
                    '}';
        }

        @Override
        public int hashCode() {
            return Objects.hash(code, success);
        }
    }
}
